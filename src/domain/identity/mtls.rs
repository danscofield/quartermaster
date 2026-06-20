// Application-layer mTLS client certificate validation for SPIRE X.509-SVIDs.
//
// Validates client certificates against the SPIRE X.509 trust bundle and
// extracts SPIFFE IDs from URI SANs. This module implements the application-layer
// validation pattern: TLS is permissive, all cert verification happens here.

use std::time::SystemTime;

use x509_parser::prelude::*;

use super::SpireIdentity;

/// Errors that can occur during mTLS validator construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsError {
    /// Trust bundle PEM parsing failed.
    InvalidTrustBundle(String),
    /// Certificate DER parsing failed.
    InvalidCertificate(String),
}

impl std::fmt::Display for MtlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MtlsError::InvalidTrustBundle(msg) => {
                write!(f, "invalid trust bundle: {}", msg)
            }
            MtlsError::InvalidCertificate(msg) => {
                write!(f, "invalid certificate: {}", msg)
            }
        }
    }
}

impl std::error::Error for MtlsError {}

/// A parsed trust anchor holding the DER-encoded certificate bytes.
#[derive(Debug, Clone)]
struct TrustAnchor {
    /// DER-encoded CA certificate bytes.
    der: Vec<u8>,
}

/// Validates a client certificate against the SPIRE X.509 trust bundle
/// and extracts the SPIFFE ID from the URI SAN.
///
/// Constructed from the CA certificates at `x509_bundle_path` (NOT from `jwks_path`,
/// which contains JWT signing keys for a different purpose).
#[derive(Debug, Clone)]
pub struct MtlsValidator {
    /// Trust anchor certificates (CA certs from SPIRE X.509 trust bundle).
    trust_anchors: Vec<TrustAnchor>,
    /// The expected SPIFFE trust domain for validation.
    trust_domain: String,
}

impl MtlsValidator {
    /// Creates a new validator from PEM-encoded CA certificates loaded from
    /// `[identity.spire].x509_bundle_path`.
    ///
    /// Returns `Err` if the PEM is malformed or contains no valid CA certs.
    pub fn from_pem(ca_pem: &[u8], trust_domain: &str) -> Result<Self, MtlsError> {
        let mut trust_anchors = Vec::new();

        for pem in Pem::iter_from_buffer(ca_pem) {
            let pem = pem.map_err(|e| {
                MtlsError::InvalidTrustBundle(format!("failed to parse PEM block: {}", e))
            })?;

            if pem.label != "CERTIFICATE" {
                continue;
            }

            // Validate that the DER content is a valid X.509 certificate
            X509Certificate::from_der(&pem.contents).map_err(|e| {
                MtlsError::InvalidTrustBundle(format!(
                    "failed to parse certificate DER: {}",
                    e
                ))
            })?;

            trust_anchors.push(TrustAnchor {
                der: pem.contents,
            });
        }

        if trust_anchors.is_empty() {
            return Err(MtlsError::InvalidTrustBundle(
                "no valid CA certificates found in PEM bundle".to_string(),
            ));
        }

        Ok(Self {
            trust_anchors,
            trust_domain: trust_domain.to_string(),
        })
    }

    /// Validates a DER-encoded client certificate.
    ///
    /// Returns `Some(SpireIdentity)` if the cert:
    /// 1. Chains to a trust anchor from `x509_bundle_path`
    /// 2. Is not expired (and not yet valid)
    /// 3. Contains a `spiffe://` URI SAN matching the expected trust domain
    ///
    /// Returns `None` (not an error) if validation fails — allowing silent fallback.
    pub fn validate(&self, cert_der: &[u8]) -> Option<SpireIdentity> {
        // Parse the client certificate
        let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

        // Check certificate validity period
        if !self.is_cert_time_valid(&cert) {
            return None;
        }

        // Verify the certificate chains to a trust anchor
        if !self.verify_chain(&cert) {
            return None;
        }

        // Extract SPIFFE ID from URI SANs
        self.extract_spiffe_identity(&cert)
    }

    /// Checks whether the certificate is currently valid (not expired, not yet valid).
    fn is_cert_time_valid(&self, cert: &X509Certificate) -> bool {
        let now = SystemTime::now();
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let now_dt = match ASN1Time::from_timestamp(secs) {
            Ok(t) => t,
            Err(_) => return false,
        };

        cert.validity().is_valid_at(now_dt)
    }

    /// Verifies that the certificate was signed by one of our trust anchors.
    ///
    /// This performs issuer matching and signature verification against each
    /// trust anchor until one succeeds.
    fn verify_chain(&self, cert: &X509Certificate) -> bool {
        for anchor in &self.trust_anchors {
            let (_, ca_cert) = match X509Certificate::from_der(&anchor.der) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };

            // Check if this CA could have issued the cert (issuer DN matches CA subject DN)
            if cert.issuer() != ca_cert.subject() {
                continue;
            }

            // Verify the signature on the certificate using the CA's public key
            if cert.verify_signature(Some(ca_cert.public_key())).is_ok() {
                return true;
            }
        }

        false
    }

    /// Extracts a SPIFFE identity from the certificate's URI SANs.
    ///
    /// Looks for a `spiffe://{trust_domain}/...` URI SAN and parses
    /// environment and region from the path segments.
    fn extract_spiffe_identity(&self, cert: &X509Certificate) -> Option<SpireIdentity> {
        // Get the Subject Alternative Name extension
        let san_ext = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?;

        let san = match san_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san,
            _ => return None,
        };

        // Look for a spiffe:// URI SAN matching our trust domain
        let spiffe_prefix = format!("spiffe://{}/", self.trust_domain);

        for name in &san.general_names {
            if let GeneralName::URI(uri) = name {
                if uri.starts_with(&spiffe_prefix) {
                    let spiffe_id = uri.to_string();
                    let path = &spiffe_id[spiffe_prefix.len()..];
                    let (environment, region) = parse_spiffe_path_segments(path);

                    return Some(SpireIdentity {
                        spiffe_id,
                        trust_domain: self.trust_domain.clone(),
                        environment,
                        region,
                        audience: vec![], // X.509-SVIDs don't carry audience
                    });
                }
            }
        }

        None
    }
}

/// Parses environment and region from SPIFFE ID path segments.
///
/// Supports patterns like:
/// - `env/{environment}/region/{region}/...`
/// - `ns/{namespace}/workload/{name}` (no env/region, defaults to empty)
///
/// Returns (environment, region) tuple, defaulting to empty strings.
fn parse_spiffe_path_segments(path: &str) -> (String, String) {
    let segments: Vec<&str> = path.split('/').collect();
    let mut environment = String::new();
    let mut region = String::new();

    let mut i = 0;
    while i < segments.len() {
        match segments[i] {
            "env" | "environment" => {
                if i + 1 < segments.len() {
                    environment = segments[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "region" => {
                if i + 1 < segments.len() {
                    region = segments[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    (environment, region)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spiffe_path_segments_with_env_and_region() {
        let (env, region) = parse_spiffe_path_segments("env/production/region/us-east-1/workload/api");
        assert_eq!(env, "production");
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn test_parse_spiffe_path_segments_no_env_no_region() {
        let (env, region) = parse_spiffe_path_segments("ns/default/workload/api");
        assert_eq!(env, "");
        assert_eq!(region, "");
    }

    #[test]
    fn test_parse_spiffe_path_segments_env_only() {
        let (env, region) = parse_spiffe_path_segments("env/staging/workload/api");
        assert_eq!(env, "staging");
        assert_eq!(region, "");
    }

    #[test]
    fn test_parse_spiffe_path_segments_environment_keyword() {
        let (env, region) = parse_spiffe_path_segments("environment/dev/region/eu-west-1");
        assert_eq!(env, "dev");
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_parse_spiffe_path_segments_empty_path() {
        let (env, region) = parse_spiffe_path_segments("");
        assert_eq!(env, "");
        assert_eq!(region, "");
    }

    #[test]
    fn test_mtls_error_display() {
        let err = MtlsError::InvalidTrustBundle("bad pem".into());
        assert_eq!(format!("{}", err), "invalid trust bundle: bad pem");

        let err = MtlsError::InvalidCertificate("bad der".into());
        assert_eq!(format!("{}", err), "invalid certificate: bad der");
    }

    #[test]
    fn test_from_pem_empty_input() {
        let result = MtlsValidator::from_pem(b"", "example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            MtlsError::InvalidTrustBundle(msg) => {
                assert!(msg.contains("no valid CA certificates"));
            }
            _ => panic!("expected InvalidTrustBundle"),
        }
    }

    #[test]
    fn test_from_pem_not_a_certificate() {
        // PEM block that's not a CERTIFICATE label
        let non_cert_pem = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----\n";
        let result = MtlsValidator::from_pem(non_cert_pem, "example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            MtlsError::InvalidTrustBundle(msg) => {
                assert!(msg.contains("no valid CA certificates"));
            }
            _ => panic!("expected InvalidTrustBundle"),
        }
    }

    #[test]
    fn test_from_pem_malformed_certificate() {
        // PEM block with CERTIFICATE label but garbage content
        let bad_cert_pem = b"-----BEGIN CERTIFICATE-----\nTm90QVZhbGlkQ2VydA==\n-----END CERTIFICATE-----\n";
        let result = MtlsValidator::from_pem(bad_cert_pem, "example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            MtlsError::InvalidTrustBundle(msg) => {
                assert!(msg.contains("failed to parse certificate DER"));
            }
            _ => panic!("expected InvalidTrustBundle"),
        }
    }

    #[test]
    fn test_validate_invalid_der_returns_none() {
        // Create a validator with a real CA cert first
        let ca_pem = generate_test_ca_pem();
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com").unwrap();

        // Pass garbage DER
        let result = validator.validate(&[0x00, 0x01, 0x02]);
        assert!(result.is_none());
    }

    #[test]
    fn test_from_pem_valid_ca() {
        let ca_pem = generate_test_ca_pem();
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com");
        assert!(validator.is_ok());
        let v = validator.unwrap();
        assert_eq!(v.trust_domain, "example.com");
        assert_eq!(v.trust_anchors.len(), 1);
    }

    #[test]
    fn test_validate_valid_cert_with_spiffe_san() {
        let (ca_pem, cert_der) = generate_test_cert_with_spiffe_san(
            "example.com",
            "spiffe://example.com/env/production/region/us-east-1/workload/api",
            false,
        );
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com").unwrap();
        let result = validator.validate(&cert_der);
        assert!(result.is_some());
        let identity = result.unwrap();
        assert_eq!(
            identity.spiffe_id,
            "spiffe://example.com/env/production/region/us-east-1/workload/api"
        );
        assert_eq!(identity.trust_domain, "example.com");
        assert_eq!(identity.environment, "production");
        assert_eq!(identity.region, "us-east-1");
        assert!(identity.audience.is_empty());
    }

    #[test]
    fn test_validate_wrong_trust_domain_returns_none() {
        let (ca_pem, cert_der) = generate_test_cert_with_spiffe_san(
            "example.com",
            "spiffe://other-domain.com/workload/api",
            false,
        );
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com").unwrap();
        let result = validator.validate(&cert_der);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_expired_cert_returns_none() {
        let (ca_pem, cert_der) = generate_test_cert_with_spiffe_san(
            "example.com",
            "spiffe://example.com/workload/api",
            true, // expired
        );
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com").unwrap();
        let result = validator.validate(&cert_der);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_untrusted_cert_returns_none() {
        // Create cert signed by a different CA than the one in the validator
        let (_, cert_der) = generate_test_cert_with_spiffe_san(
            "example.com",
            "spiffe://example.com/workload/api",
            false,
        );
        // Use a different CA for the validator
        let other_ca_pem = generate_test_ca_pem();
        let validator = MtlsValidator::from_pem(&other_ca_pem, "example.com").unwrap();
        let result = validator.validate(&cert_der);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_no_uri_san_returns_none() {
        let (ca_pem, cert_der) = generate_test_cert_no_san();
        let validator = MtlsValidator::from_pem(&ca_pem, "example.com").unwrap();
        let result = validator.validate(&cert_der);
        assert!(result.is_none());
    }

    // ---- Test helpers using openssl for certificate generation ----

    fn generate_test_ca_pem() -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509NameBuilder, X509};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test CA").unwrap();
        let name = name_builder.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let ca_cert = builder.build();
        ca_cert.to_pem().unwrap()
    }

    fn generate_test_cert_with_spiffe_san(
        _trust_domain: &str,
        spiffe_id: &str,
        expired: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
        use openssl::x509::{X509NameBuilder, X509};

        // Generate CA
        let ca_rsa = Rsa::generate(2048).unwrap();
        let ca_pkey = PKey::from_rsa(ca_rsa).unwrap();

        let mut ca_name_builder = X509NameBuilder::new().unwrap();
        ca_name_builder
            .append_entry_by_text("CN", "Test CA")
            .unwrap();
        let ca_name = ca_name_builder.build();

        let mut ca_builder = X509::builder().unwrap();
        ca_builder.set_version(2).unwrap();
        ca_builder.set_subject_name(&ca_name).unwrap();
        ca_builder.set_issuer_name(&ca_name).unwrap();
        ca_builder.set_pubkey(&ca_pkey).unwrap();
        ca_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        ca_builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        ca_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        ca_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let ca_cert = ca_builder.build();
        let ca_pem = ca_cert.to_pem().unwrap();

        // Generate leaf certificate signed by CA
        let leaf_rsa = Rsa::generate(2048).unwrap();
        let leaf_pkey = PKey::from_rsa(leaf_rsa).unwrap();

        let mut leaf_name_builder = X509NameBuilder::new().unwrap();
        leaf_name_builder
            .append_entry_by_text("CN", "workload")
            .unwrap();
        let leaf_name = leaf_name_builder.build();

        let mut leaf_builder = X509::builder().unwrap();
        leaf_builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(2).unwrap();
        leaf_builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        leaf_builder.set_subject_name(&leaf_name).unwrap();
        leaf_builder.set_issuer_name(&ca_name).unwrap();
        leaf_builder.set_pubkey(&leaf_pkey).unwrap();

        if expired {
            // Set cert to be already expired using Asn1Time::from_str with past dates
            use openssl::asn1::Asn1Time as OsslTime;
            let not_before = OsslTime::from_str("20200101000000Z").unwrap();
            let not_after = OsslTime::from_str("20200102000000Z").unwrap();
            leaf_builder.set_not_before(&not_before).unwrap();
            leaf_builder.set_not_after(&not_after).unwrap();
        } else {
            leaf_builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            leaf_builder
                .set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();
        }

        leaf_builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();

        // Add URI SAN with SPIFFE ID
        let san = SubjectAlternativeName::new()
            .uri(spiffe_id)
            .build(&leaf_builder.x509v3_context(Some(&ca_cert), None))
            .unwrap();
        leaf_builder.append_extension(san).unwrap();

        leaf_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let leaf_cert = leaf_builder.build();
        let cert_der = leaf_cert.to_der().unwrap();

        (ca_pem, cert_der)
    }

    fn generate_test_cert_no_san() -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509NameBuilder, X509};

        // Generate CA
        let ca_rsa = Rsa::generate(2048).unwrap();
        let ca_pkey = PKey::from_rsa(ca_rsa).unwrap();

        let mut ca_name_builder = X509NameBuilder::new().unwrap();
        ca_name_builder
            .append_entry_by_text("CN", "Test CA")
            .unwrap();
        let ca_name = ca_name_builder.build();

        let mut ca_builder = X509::builder().unwrap();
        ca_builder.set_version(2).unwrap();
        ca_builder.set_subject_name(&ca_name).unwrap();
        ca_builder.set_issuer_name(&ca_name).unwrap();
        ca_builder.set_pubkey(&ca_pkey).unwrap();
        ca_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        ca_builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        ca_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        ca_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let ca_cert = ca_builder.build();
        let ca_pem = ca_cert.to_pem().unwrap();

        // Generate leaf cert without SAN
        let leaf_rsa = Rsa::generate(2048).unwrap();
        let leaf_pkey = PKey::from_rsa(leaf_rsa).unwrap();

        let mut leaf_name_builder = X509NameBuilder::new().unwrap();
        leaf_name_builder
            .append_entry_by_text("CN", "workload")
            .unwrap();
        let leaf_name = leaf_name_builder.build();

        let mut leaf_builder = X509::builder().unwrap();
        leaf_builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(3).unwrap();
        leaf_builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        leaf_builder.set_subject_name(&leaf_name).unwrap();
        leaf_builder.set_issuer_name(&ca_name).unwrap();
        leaf_builder.set_pubkey(&leaf_pkey).unwrap();
        leaf_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        leaf_builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        leaf_builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        leaf_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let leaf_cert = leaf_builder.build();
        let cert_der = leaf_cert.to_der().unwrap();

        (ca_pem, cert_der)
    }
}
