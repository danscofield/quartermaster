pub mod kms_authority;

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use ring::rand::SystemRandom;
use ring::signature::{self, UnparsedPublicKey};
use time::OffsetDateTime;

/// Request parameters for certificate issuance.
#[derive(Debug)]
pub struct CertIssueRequest {
    pub csr_der: Vec<u8>,
    pub spiffe_id: String,
    pub billets: Vec<String>,
}

/// Response containing the issued certificate chain.
#[derive(Debug, Clone)]
pub struct CertIssueResponse {
    pub leaf_pem: Vec<u8>,
    pub intermediate_pem: Vec<u8>,
    pub chain_pem: Vec<u8>, // leaf + intermediate concatenated
}

/// Errors that can occur during certificate issuance.
#[derive(Debug, Clone)]
pub enum CertError {
    /// CSR couldn't be parsed or has invalid self-signature
    InvalidCsr(String),
    /// Certificate signing failed
    SigningFailed(String),
    /// CA is not initialized
    CaNotReady(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::InvalidCsr(msg) => write!(f, "invalid CSR: {}", msg),
            CertError::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            CertError::CaNotReady(msg) => write!(f, "CA not ready: {}", msg),
        }
    }
}

impl std::error::Error for CertError {}

/// Authority issues short-lived X.509 certificates.
#[async_trait::async_trait]
pub trait Authority: Send + Sync {
    /// Issue creates a certificate using the public key from the CSR,
    /// populating identity and billets from authenticated context.
    async fn issue(&self, req: CertIssueRequest) -> Result<CertIssueResponse, CertError>;

    /// Returns the CA certificate chain in PEM format.
    fn chain_pem(&self) -> &[u8];
}

/// Local certificate authority backed by an in-memory CA key and certificate.
pub struct LocalAuthority {
    ca_key_pair: Arc<KeyPair>,
    ca_cert_pem: Vec<u8>,
    ca_cert_params: Arc<CertificateParams>,
    ttl: Duration,
    _rng: SystemRandom,
}

impl std::fmt::Debug for LocalAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAuthority")
            .field("ttl", &self.ttl)
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .finish_non_exhaustive()
    }
}

impl LocalAuthority {
    /// Creates a new LocalAuthority from PEM-encoded CA key and certificate.
    ///
    /// # Arguments
    /// * `ca_key_pem` - PEM-encoded CA private key
    /// * `ca_cert_pem` - PEM-encoded CA certificate
    /// * `ttl` - Default certificate validity duration
    pub fn new(
        ca_key_pem: &str,
        ca_cert_pem: &str,
        ttl: Duration,
    ) -> Result<Self, CertError> {
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)
            .map_err(|e| CertError::CaNotReady(format!("failed to parse CA key: {}", e)))?;

        let ca_cert_params =
            CertificateParams::from_ca_cert_pem(ca_cert_pem)
                .map_err(|e| CertError::CaNotReady(format!("failed to parse CA cert: {}", e)))?;

        Ok(Self {
            ca_key_pair: Arc::new(ca_key_pair),
            ca_cert_pem: ca_cert_pem.as_bytes().to_vec(),
            ca_cert_params: Arc::new(ca_cert_params),
            ttl,
            _rng: SystemRandom::new(),
        })
    }

    /// Extract the trust domain from a SPIFFE ID or use a default for non-SPIFFE subjects.
    /// e.g., "spiffe://example.org/workload" -> "example.org"
    /// e.g., "aws:123:rolename" -> "quartermaster"
    pub(crate) fn extract_trust_domain(spiffe_id: &str) -> Result<&str, CertError> {
        if let Some(stripped) = spiffe_id.strip_prefix("spiffe://") {
            stripped.split('/').next().ok_or_else(|| {
                CertError::InvalidCsr(format!("cannot extract trust domain from: {}", spiffe_id))
            })
        } else {
            // Non-SPIFFE identity (AWS, OIDC, GCP) — use "quartermaster" as the billet URI domain
            Ok("quartermaster")
        }
    }

    /// Verify the self-signature on a CSR using ring.
    /// Returns the SubjectPublicKeyInfo DER bytes on success.
    pub(crate) fn verify_csr_signature(csr_der: &[u8]) -> Result<(), CertError> {
        // A PKCS#10 CSR has the ASN.1 structure:
        // CertificationRequest ::= SEQUENCE {
        //   certificationRequestInfo  CertificationRequestInfo,
        //   signatureAlgorithm        AlgorithmIdentifier,
        //   signature                 BIT STRING
        // }
        //
        // CertificationRequestInfo ::= SEQUENCE {
        //   version       INTEGER,
        //   subject       Name,
        //   subjectPKInfo SubjectPublicKeyInfo,
        //   attributes    [0] IMPLICIT SET OF Attribute
        // }
        //
        // We parse the outer SEQUENCE, extract the certificationRequestInfo bytes (the TBS),
        // the algorithm, and signature, then verify with ring.

        use ring::io::der as ring_der;

        // Parse outer SEQUENCE
        let reader = untrusted::Input::from(csr_der);
        let (tbs_bytes, spki_bytes, algorithm_oid, sig_bytes) = reader
            .read_all(ring::error::Unspecified, |input| {
                ring_der::nested(input, ring_der::Tag::Sequence, ring::error::Unspecified, |seq| {
                    // Record position of certificationRequestInfo
                    let tbs_input = ring_der::expect_tag_and_get_value(seq, ring_der::Tag::Sequence)
                        .map_err(|_| ring::error::Unspecified)?;

                    // Re-encode the TBS with tag+length for signature verification
                    // We need the raw bytes as they appeared in the original DER
                    let tbs_bytes = tbs_input.as_slice_less_safe();

                    // Parse inside the certificationRequestInfo to get SPKI
                    let spki_bytes = {
                        let mut tbs_reader = untrusted::Reader::new(tbs_input);
                        // Skip version INTEGER
                        ring_der::expect_tag_and_get_value(&mut tbs_reader, ring_der::Tag::Integer)
                            .map_err(|_| ring::error::Unspecified)?;
                        // Skip subject SEQUENCE
                        ring_der::expect_tag_and_get_value(
                            &mut tbs_reader,
                            ring_der::Tag::Sequence,
                        )
                        .map_err(|_| ring::error::Unspecified)?;
                        // SubjectPublicKeyInfo SEQUENCE
                        let spki = ring_der::expect_tag_and_get_value(
                            &mut tbs_reader,
                            ring_der::Tag::Sequence,
                        )
                        .map_err(|_| ring::error::Unspecified)?;
                        spki.as_slice_less_safe().to_vec()
                    };

                    // signatureAlgorithm SEQUENCE
                    let alg_seq = ring_der::expect_tag_and_get_value(seq, ring_der::Tag::Sequence)
                        .map_err(|_| ring::error::Unspecified)?;
                    // Extract the OID from the algorithm sequence
                    let alg_oid = {
                        let mut alg_reader = untrusted::Reader::new(alg_seq);
                        let oid = ring_der::expect_tag_and_get_value(
                            &mut alg_reader,
                            ring_der::Tag::OID,
                        )
                        .map_err(|_| ring::error::Unspecified)?;
                        oid.as_slice_less_safe().to_vec()
                    };

                    // signature BIT STRING
                    let sig_bit_string =
                        ring_der::bit_string_with_no_unused_bits(seq)
                            .map_err(|_| ring::error::Unspecified)?;
                    let sig_bytes = sig_bit_string.as_slice_less_safe().to_vec();

                    Ok((tbs_bytes.to_vec(), spki_bytes, alg_oid, sig_bytes))
                })
            })
            .map_err(|_| CertError::InvalidCsr("failed to parse CSR DER structure".to_string()))?;

        // We need to reconstruct the full TBS with tag and length for verification.
        // The tbs_bytes is just the content of the SEQUENCE. We need the complete
        // SEQUENCE encoding (tag + length + content).
        let tbs_with_tag = encode_sequence(&tbs_bytes);

        // Determine the signature verification algorithm from the OID
        let verification_alg = oid_to_ring_algorithm(&algorithm_oid)?;

        // Extract the raw public key from SubjectPublicKeyInfo
        let public_key_bytes = extract_public_key_from_spki(&spki_bytes)?;

        // Verify the signature
        let public_key =
            UnparsedPublicKey::new(verification_alg, &public_key_bytes);
        public_key
            .verify(&tbs_with_tag, &sig_bytes)
            .map_err(|_| CertError::InvalidCsr("CSR self-signature verification failed".to_string()))
    }
}

/// Encode raw content bytes as a DER SEQUENCE (tag 0x30 + length + content).
fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE tag
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Encode a DER length.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len < 0x1000000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Extract the raw public key bytes from a SubjectPublicKeyInfo DER content.
/// SPKI structure:
///   SEQUENCE {
///     algorithm AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
///   }
/// We receive just the content of the SEQUENCE (without tag/length).
fn extract_public_key_from_spki(spki_content: &[u8]) -> Result<Vec<u8>, CertError> {
    let input = untrusted::Input::from(spki_content);
    input
        .read_all(ring::error::Unspecified, |reader| {
            use ring::io::der as ring_der;
            // Skip AlgorithmIdentifier SEQUENCE
            ring_der::expect_tag_and_get_value(reader, ring_der::Tag::Sequence)
                .map_err(|_| ring::error::Unspecified)?;
            // Read BIT STRING (the public key)
            let pk = ring_der::bit_string_with_no_unused_bits(reader)
                .map_err(|_| ring::error::Unspecified)?;
            Ok(pk.as_slice_less_safe().to_vec())
        })
        .map_err(|_| CertError::InvalidCsr("failed to extract public key from SPKI".to_string()))
}

/// Map a signature algorithm OID to a ring verification algorithm.
fn oid_to_ring_algorithm(
    oid: &[u8],
) -> Result<&'static dyn signature::VerificationAlgorithm, CertError> {
    // Common OIDs:
    // ECDSA with SHA-256: 1.2.840.10045.4.3.2 -> [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
    // ECDSA with SHA-384: 1.2.840.10045.4.3.3 -> [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]
    // RSA with SHA-256:   1.2.840.113549.1.1.11 -> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    // RSA with SHA-384:   1.2.840.113549.1.1.12 -> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C]
    // RSA with SHA-512:   1.2.840.113549.1.1.13 -> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D]
    // Ed25519:            1.3.101.112 -> [0x2B, 0x65, 0x70]
    match oid {
        // ECDSA with SHA-256
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] => {
            Ok(&signature::ECDSA_P256_SHA256_ASN1)
        }
        // ECDSA with SHA-384
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => {
            Ok(&signature::ECDSA_P384_SHA384_ASN1)
        }
        // Ed25519
        [0x2B, 0x65, 0x70] => Ok(&signature::ED25519),
        // RSA PKCS#1 v1.5 with SHA-256
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B] => {
            Ok(&signature::RSA_PKCS1_2048_8192_SHA256)
        }
        // RSA PKCS#1 v1.5 with SHA-384
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C] => {
            Ok(&signature::RSA_PKCS1_2048_8192_SHA384)
        }
        // RSA PKCS#1 v1.5 with SHA-512
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D] => {
            Ok(&signature::RSA_PKCS1_2048_8192_SHA512)
        }
        _ => Err(CertError::InvalidCsr(format!(
            "unsupported signature algorithm OID: {:?}",
            oid
        ))),
    }
}

#[async_trait::async_trait]
impl Authority for LocalAuthority {
    async fn issue(&self, req: CertIssueRequest) -> Result<CertIssueResponse, CertError> {
        // 1. Verify CSR self-signature
        Self::verify_csr_signature(&req.csr_der)?;

        // 2. Parse CSR using rcgen to extract the public key
        //    We use rcgen's from_der which validates and extracts the public key.
        //    We then discard the params (Subject, SANs, extensions) from the CSR.
        let csr_der_ref: &[u8] = &req.csr_der;
        let csr_der_typed = csr_der_ref.into();
        let csr_params = CertificateSigningRequestParams::from_der(&csr_der_typed)
            .map_err(|e| CertError::InvalidCsr(format!("failed to parse CSR: {}", e)))?;

        // 3. Extract trust domain from SPIFFE ID
        let trust_domain = Self::extract_trust_domain(&req.spiffe_id)?;

        // 4. Build certificate parameters - discard CSR Subject/SANs/extensions
        let mut params = CertificateParams::default();

        // Subject CN = SPIFFE ID
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &req.spiffe_id);
        params.distinguished_name = dn;

        // URI SANs: SPIFFE ID + qm-billet://{trust_domain}/{billet} for each billet
        let spiffe_ia5 = Ia5String::try_from(req.spiffe_id.as_str())
            .map_err(|e| CertError::SigningFailed(format!("invalid SPIFFE ID for IA5String: {}", e)))?;
        let mut sans = vec![SanType::URI(spiffe_ia5)];
        for billet in &req.billets {
            let uri = format!("qm-billet://{}/{}", trust_domain, billet);
            let ia5 = Ia5String::try_from(uri.as_str())
                .map_err(|e| CertError::SigningFailed(format!("invalid billet URI for IA5String: {}", e)))?;
            sans.push(SanType::URI(ia5));
        }
        params.subject_alt_names = sans;

        // Validity = configured TTL
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(self.ttl.as_secs() as i64);

        // Key Usage: Digital Signature | Key Encipherment
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Extended Key Usage: Client Auth + Server Auth
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];

        // Not a CA
        params.is_ca = IsCa::NoCa;

        // Random serial number
        let serial = generate_random_serial()?;
        params.serial_number = Some(serial);

        // 5. Sign with CA key
        let ca_params_clone = (*self.ca_cert_params).clone();
        let ca_cert = ca_params_clone
            .self_signed(&self.ca_key_pair)
            .map_err(|e| CertError::SigningFailed(format!("failed to create CA cert: {}", e)))?;

        let leaf_cert = params
            .signed_by(&csr_params.public_key, &ca_cert, &self.ca_key_pair)
            .map_err(|e| CertError::SigningFailed(format!("failed to sign leaf cert: {}", e)))?;

        // 6. Get PEM output
        let leaf_pem = leaf_cert.pem().into_bytes();
        let intermediate_pem = self.ca_cert_pem.clone();

        // Chain = leaf + intermediate
        let mut chain_pem = leaf_pem.clone();
        chain_pem.extend_from_slice(&intermediate_pem);

        Ok(CertIssueResponse {
            leaf_pem,
            intermediate_pem,
            chain_pem,
        })
    }

    fn chain_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }
}

/// Generate a random 20-byte serial number.
pub(crate) fn generate_random_serial() -> Result<SerialNumber, CertError> {
    let rng = SystemRandom::new();
    let mut serial_bytes = [0u8; 20];
    ring::rand::SecureRandom::fill(&rng, &mut serial_bytes)
        .map_err(|_| CertError::SigningFailed("failed to generate random serial".to_string()))?;
    // Ensure the first byte is not 0x00 or >= 0x80 to keep it positive and non-zero
    serial_bytes[0] = (serial_bytes[0] & 0x7F) | 0x01;
    Ok(SerialNumber::from_slice(&serial_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA key pair and certificate for testing.
    fn generate_test_ca() -> (String, String) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        ca_params.distinguished_name = dn;
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        (ca_key.serialize_pem(), ca_cert.pem())
    }

    /// Generate a CSR (DER) for testing with the given key pair.
    fn generate_test_csr() -> (Vec<u8>, KeyPair) {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-workload");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName("test.example.com".try_into().unwrap())];

        let csr = params.serialize_request(&key_pair).unwrap();
        (csr.der().to_vec(), key_pair)
    }

    #[tokio::test]
    async fn test_issue_certificate_success() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
            .expect("failed to create authority");

        let (csr_der, _key_pair) = generate_test_csr();

        let req = CertIssueRequest {
            csr_der,
            spiffe_id: "spiffe://example.org/workload/my-service".to_string(),
            billets: vec!["billing".to_string(), "analytics".to_string()],
        };

        let response = authority.issue(req).await.expect("issue should succeed");

        // Verify response contains PEM data
        let leaf_str = String::from_utf8(response.leaf_pem.clone()).unwrap();
        assert!(leaf_str.contains("BEGIN CERTIFICATE"));
        assert!(leaf_str.contains("END CERTIFICATE"));

        let intermediate_str = String::from_utf8(response.intermediate_pem.clone()).unwrap();
        assert!(intermediate_str.contains("BEGIN CERTIFICATE"));

        // Chain should contain both
        let chain_str = String::from_utf8(response.chain_pem.clone()).unwrap();
        assert!(chain_str.contains("BEGIN CERTIFICATE"));
        // Should have two certificates in the chain
        let cert_count = chain_str.matches("BEGIN CERTIFICATE").count();
        assert_eq!(cert_count, 2, "chain should contain leaf + intermediate");
    }

    #[tokio::test]
    async fn test_issue_certificate_invalid_csr() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
            .expect("failed to create authority");

        let req = CertIssueRequest {
            csr_der: vec![0x30, 0x00], // invalid/empty CSR
            spiffe_id: "spiffe://example.org/workload/my-service".to_string(),
            billets: vec!["billing".to_string()],
        };

        let result = authority.issue(req).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::InvalidCsr(_) => {} // expected
            other => panic!("expected InvalidCsr, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_issue_certificate_corrupted_csr_signature() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
            .expect("failed to create authority");

        let (mut csr_der, _key_pair) = generate_test_csr();
        // Corrupt the last few bytes (part of the signature)
        let len = csr_der.len();
        if len > 4 {
            csr_der[len - 1] ^= 0xFF;
            csr_der[len - 2] ^= 0xFF;
        }

        let req = CertIssueRequest {
            csr_der,
            spiffe_id: "spiffe://example.org/workload/my-service".to_string(),
            billets: vec!["billing".to_string()],
        };

        let result = authority.issue(req).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::InvalidCsr(_) => {} // expected - signature verification should fail
            other => panic!("expected InvalidCsr, got: {:?}", other),
        }
    }

    #[test]
    fn test_chain_pem_returns_ca_cert() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
            .expect("failed to create authority");

        let chain = authority.chain_pem();
        let chain_str = std::str::from_utf8(chain).unwrap();
        assert!(chain_str.contains("BEGIN CERTIFICATE"));
        assert_eq!(chain_str, ca_cert_pem);
    }

    #[test]
    fn test_extract_trust_domain() {
        let td = LocalAuthority::extract_trust_domain("spiffe://example.org/workload/svc")
            .unwrap();
        assert_eq!(td, "example.org");

        let td = LocalAuthority::extract_trust_domain("spiffe://my-domain.com/ns/default/sa/app")
            .unwrap();
        assert_eq!(td, "my-domain.com");

        let result = LocalAuthority::extract_trust_domain("http://not-spiffe/foo");
        assert_eq!(result.unwrap(), "quartermaster");
    }

    #[test]
    fn test_invalid_ca_key() {
        let (_, ca_cert_pem) = generate_test_ca();
        let result = LocalAuthority::new("not a valid pem", &ca_cert_pem, Duration::from_secs(300));
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::CaNotReady(_) => {} // expected
            other => panic!("expected CaNotReady, got: {:?}", other),
        }
    }

    #[test]
    fn test_random_serial_uniqueness() {
        let s1 = generate_random_serial().unwrap();
        let s2 = generate_random_serial().unwrap();
        // Extremely unlikely to be equal
        assert_ne!(format!("{:?}", s1), format!("{:?}", s2));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use x509_parser::prelude::*;

    /// Generate a self-signed CA key pair and certificate for testing.
    fn generate_test_ca() -> (String, String) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        ca_params.distinguished_name = dn;
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        (ca_key.serialize_pem(), ca_cert.pem())
    }

    /// Strategy for generating valid SPIFFE IDs.
    fn spiffe_id_strategy() -> impl Strategy<Value = String> {
        (
            "[a-z][a-z0-9]{1,8}\\.[a-z]{2,4}",
            prop::collection::vec("[a-z][a-z0-9]{1,8}", 1..4),
        )
            .prop_map(|(domain, segments)| {
                format!("spiffe://{}/{}", domain, segments.join("/"))
            })
    }

    /// Strategy for generating billet name sets (non-empty, unique names).
    fn billets_strategy() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-z][a-z0-9\\-]{1,12}", 1..5)
            .prop_map(|mut v| {
                v.sort();
                v.dedup();
                if v.is_empty() {
                    v.push("default-billet".to_string());
                }
                v
            })
    }

    /// Strategy for generating a TTL in seconds (between 60 and 3600).
    fn ttl_strategy() -> impl Strategy<Value = u64> {
        60u64..=3600u64
    }

    /// Strategy for generating arbitrary CSR subject CN values (to verify they get discarded).
    fn csr_cn_strategy() -> impl Strategy<Value = String> {
        "[A-Z][a-zA-Z0-9 ]{1,20}"
    }

    /// Strategy for generating arbitrary DNS SANs for the CSR (to verify they get discarded).
    fn csr_dns_sans_strategy() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-z]{1,8}\\.[a-z]{2,4}", 0..3)
    }

    /// Generate a CSR with arbitrary Subject CN and DNS SANs that should be discarded.
    /// Returns (csr_der, key_pair_public_key_der).
    fn generate_csr_with_arbitrary_fields(cn: &str, dns_sans: &[String]) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn.push(DnType::OrganizationName, "Arbitrary Org");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;
        params.subject_alt_names = dns_sans
            .iter()
            .filter_map(|s| {
                Some(SanType::DnsName(s.as_str().try_into().ok()?))
            })
            .collect();

        let csr = params.serialize_request(&key_pair).unwrap();
        let public_key_der = key_pair.public_key_der().to_vec();
        (csr.der().to_vec(), public_key_der)
    }

    // Feature: quartermaster, Property 5: Certificate Construction Correctness
    //
    // Generate random key pairs and CSRs (with arbitrary Subject/SANs), random SPIFFE IDs
    // and billet sets.
    // Assert: pubkey matches CSR, CN == SPIFFE ID, URI SANs correct, validity == TTL,
    //         KU/EKU correct, CSR Subject/SANs discarded
    //
    // **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.9, 15.3, 15.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_certificate_construction_correctness(
            spiffe_id in spiffe_id_strategy(),
            billets in billets_strategy(),
            ttl_secs in ttl_strategy(),
            csr_cn in csr_cn_strategy(),
            csr_dns_sans in csr_dns_sans_strategy(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let (ca_key_pem, ca_cert_pem) = generate_test_ca();
                let ttl = Duration::from_secs(ttl_secs);
                let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, ttl)
                    .expect("failed to create authority");

                // Generate CSR with arbitrary Subject/SANs that should be discarded
                let (csr_der, csr_public_key_der) =
                    generate_csr_with_arbitrary_fields(&csr_cn, &csr_dns_sans);

                let req = CertIssueRequest {
                    csr_der,
                    spiffe_id: spiffe_id.clone(),
                    billets: billets.clone(),
                };

                let response = authority.issue(req).await.expect("issue should succeed");

                // Parse the issued leaf certificate
                let leaf_pem_str = String::from_utf8(response.leaf_pem.clone()).unwrap();
                let pem = x509_parser::pem::Pem::iter_from_buffer(leaf_pem_str.as_bytes())
                    .next()
                    .unwrap()
                    .unwrap();
                let (_, cert) = X509Certificate::from_der(&pem.contents).unwrap();

                // (a) Public key in cert matches public key in CSR
                let cert_pubkey_raw = cert.public_key().raw;
                // The csr_public_key_der is the SubjectPublicKeyInfo DER.
                // The cert's public_key().raw is also SubjectPublicKeyInfo.
                prop_assert_eq!(
                    cert_pubkey_raw, csr_public_key_der.as_slice(),
                    "cert public key must match CSR public key"
                );

                // (b) Subject CN == SPIFFE ID
                let subject_cn = cert
                    .subject()
                    .iter_common_name()
                    .next()
                    .expect("cert must have a CN");
                let cn_str = subject_cn.as_str().unwrap();
                prop_assert_eq!(
                    cn_str, &spiffe_id,
                    "Subject CN must equal the SPIFFE ID"
                );

                // (c) URI SANs include the SPIFFE ID and one qm-billet:// URI per billet
                let san_ext = cert
                    .extensions()
                    .iter()
                    .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
                    .expect("cert must have SAN extension");
                let san_parsed = match san_ext.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => san,
                    _ => panic!("expected SubjectAlternativeName"),
                };

                let uri_sans: Vec<&str> = san_parsed
                    .general_names
                    .iter()
                    .filter_map(|gn| match gn {
                        GeneralName::URI(uri) => Some(*uri),
                        _ => None,
                    })
                    .collect();

                // Must contain the SPIFFE ID URI
                prop_assert!(
                    uri_sans.contains(&spiffe_id.as_str()),
                    "URI SANs must include the SPIFFE ID: {:?} not in {:?}",
                    spiffe_id, uri_sans
                );

                // Extract trust domain from SPIFFE ID
                let trust_domain = spiffe_id
                    .strip_prefix("spiffe://")
                    .unwrap()
                    .split('/')
                    .next()
                    .unwrap();

                // Must contain one qm-billet:// URI per billet
                for billet in &billets {
                    let expected_uri = format!("qm-billet://{}/{}", trust_domain, billet);
                    prop_assert!(
                        uri_sans.contains(&expected_uri.as_str()),
                        "URI SANs must include billet URI {}: {:?}",
                        expected_uri, uri_sans
                    );
                }

                // Total URI SANs = 1 (SPIFFE ID) + billets.len()
                prop_assert_eq!(
                    uri_sans.len(), 1 + billets.len(),
                    "URI SANs count must be 1 (SPIFFE ID) + number of billets"
                );

                // (d) No DNS SANs from CSR should be present
                let dns_sans: Vec<&str> = san_parsed
                    .general_names
                    .iter()
                    .filter_map(|gn| match gn {
                        GeneralName::DNSName(dns) => Some(*dns),
                        _ => None,
                    })
                    .collect();
                prop_assert!(
                    dns_sans.is_empty(),
                    "CSR's DNS SANs must be discarded, found: {:?}",
                    dns_sans
                );

                // (e) Validity period equals TTL (within 2 seconds tolerance for clock)
                let not_before = cert.validity().not_before.timestamp();
                let not_after = cert.validity().not_after.timestamp();
                let actual_validity = not_after - not_before;
                let expected_validity = ttl_secs as i64;
                prop_assert!(
                    (actual_validity - expected_validity).abs() <= 1,
                    "validity period must equal TTL: got {} expected {}",
                    actual_validity, expected_validity
                );

                // (f) Key Usage = Digital Signature | Key Encipherment
                let ku_ext = cert
                    .extensions()
                    .iter()
                    .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
                    .expect("cert must have Key Usage extension");
                let key_usage = match ku_ext.parsed_extension() {
                    ParsedExtension::KeyUsage(ku) => ku,
                    _ => panic!("expected KeyUsage"),
                };
                prop_assert!(
                    key_usage.digital_signature(),
                    "Key Usage must include Digital Signature"
                );
                prop_assert!(
                    key_usage.key_encipherment(),
                    "Key Usage must include Key Encipherment"
                );

                // (g) Extended Key Usage = Client Auth + Server Auth
                let eku_ext = cert
                    .extensions()
                    .iter()
                    .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
                    .expect("cert must have Extended Key Usage extension");
                let eku = match eku_ext.parsed_extension() {
                    ParsedExtension::ExtendedKeyUsage(eku) => eku,
                    _ => panic!("expected ExtendedKeyUsage"),
                };
                prop_assert!(
                    eku.client_auth,
                    "Extended Key Usage must include Client Auth"
                );
                prop_assert!(
                    eku.server_auth,
                    "Extended Key Usage must include Server Auth"
                );

                // (h) CSR Subject fields discarded — verify no O or C from CSR
                let subject_o: Vec<_> = cert
                    .subject()
                    .iter_organization()
                    .collect();
                prop_assert!(
                    subject_o.is_empty(),
                    "CSR's Organization must be discarded, found: {:?}",
                    subject_o
                );

                let subject_c: Vec<_> = cert
                    .subject()
                    .iter_country()
                    .collect();
                prop_assert!(
                    subject_c.is_empty(),
                    "CSR's Country must be discarded, found: {:?}",
                    subject_c
                );

                // Verify Subject CN is NOT the CSR's CN
                prop_assert_ne!(
                    cn_str, &csr_cn,
                    "Subject CN must NOT be the CSR's CN (must be SPIFFE ID instead)"
                );

                Ok(())
            })?;
        }
    }

    // Feature: quartermaster, Property 6: Certificate Serial Uniqueness
    //
    // Issue N certificates, collect serial numbers, assert all distinct.
    //
    // **Validates: Requirements 5.8**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_certificate_serial_uniqueness(
            spiffe_id in spiffe_id_strategy(),
            billets in billets_strategy(),
            n in 10usize..=20usize,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let (ca_key_pem, ca_cert_pem) = generate_test_ca();
                let authority = LocalAuthority::new(
                    &ca_key_pem,
                    &ca_cert_pem,
                    Duration::from_secs(300),
                )
                .expect("failed to create authority");

                let mut serial_numbers: Vec<Vec<u8>> = Vec::with_capacity(n);

                for _ in 0..n {
                    // Generate a fresh CSR for each issuance
                    let key_pair = KeyPair::generate().unwrap();
                    let mut params = CertificateParams::default();
                    let mut dn = DistinguishedName::new();
                    dn.push(DnType::CommonName, "test-workload");
                    params.distinguished_name = dn;
                    let csr = params.serialize_request(&key_pair).unwrap();
                    let csr_der = csr.der().to_vec();

                    let req = CertIssueRequest {
                        csr_der,
                        spiffe_id: spiffe_id.clone(),
                        billets: billets.clone(),
                    };

                    let response = authority.issue(req).await.expect("issue should succeed");

                    // Parse the issued certificate to extract its serial number
                    let leaf_pem_str = String::from_utf8(response.leaf_pem).unwrap();
                    let pem = x509_parser::pem::Pem::iter_from_buffer(leaf_pem_str.as_bytes())
                        .next()
                        .unwrap()
                        .unwrap();
                    let (_, cert) = X509Certificate::from_der(&pem.contents).unwrap();

                    let serial = cert.raw_serial().to_vec();
                    serial_numbers.push(serial);
                }

                // Assert all serial numbers are distinct
                let unique_count = {
                    let mut sorted = serial_numbers.clone();
                    sorted.sort();
                    sorted.dedup();
                    sorted.len()
                };

                prop_assert_eq!(
                    unique_count, serial_numbers.len(),
                    "All {} certificate serial numbers must be distinct, but only {} are unique",
                    serial_numbers.len(), unique_count
                );

                Ok(())
            })?;
        }
    }

    // Feature: quartermaster, Property 7: Certificate Chain Verification Round-Trip
    //
    // Issue certificates, verify the certificate chain against the CA trust bundle,
    // assert verification succeeds.
    //
    // **Validates: Requirements 17.1**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_certificate_chain_verification_round_trip(
            spiffe_id in spiffe_id_strategy(),
            billets in billets_strategy(),
            ttl_secs in ttl_strategy(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let (ca_key_pem, ca_cert_pem) = generate_test_ca();
                let ttl = Duration::from_secs(ttl_secs);
                let authority = LocalAuthority::new(&ca_key_pem, &ca_cert_pem, ttl)
                    .expect("failed to create authority");

                // Generate a CSR
                let key_pair = KeyPair::generate().unwrap();
                let mut params = CertificateParams::default();
                let mut dn = DistinguishedName::new();
                dn.push(DnType::CommonName, "test-workload");
                params.distinguished_name = dn;
                let csr = params.serialize_request(&key_pair).unwrap();
                let csr_der = csr.der().to_vec();

                // Issue the certificate
                let req = CertIssueRequest {
                    csr_der,
                    spiffe_id: spiffe_id.clone(),
                    billets: billets.clone(),
                };
                let response = authority.issue(req).await.expect("issue should succeed");

                // Get the CA trust bundle (chain_pem from Authority trait)
                let trust_bundle_pem = authority.chain_pem();

                // Verify the leaf certificate chain against the CA trust bundle using openssl
                let leaf_pem_bytes = &response.leaf_pem;
                let leaf_cert = openssl::x509::X509::from_pem(leaf_pem_bytes)
                    .expect("failed to parse leaf cert PEM");

                let ca_cert = openssl::x509::X509::from_pem(trust_bundle_pem)
                    .expect("failed to parse CA cert PEM");

                // Build a trusted certificate store with the CA cert
                let mut store_builder = openssl::x509::store::X509StoreBuilder::new()
                    .expect("failed to create X509 store builder");
                store_builder
                    .add_cert(ca_cert)
                    .expect("failed to add CA cert to store");
                let store = store_builder.build();

                // Create a verification context and verify the leaf cert
                let mut store_ctx = openssl::x509::X509StoreContext::new()
                    .expect("failed to create X509 store context");

                // The intermediate_pem in this setup is the same as the CA cert
                // (single-level CA), so the chain is just the leaf signed by the CA.
                let chain = openssl::stack::Stack::<openssl::x509::X509>::new()
                    .expect("failed to create X509 stack");

                let verify_result = store_ctx
                    .init(&store, &leaf_cert, &chain, |ctx| ctx.verify_cert())
                    .expect("failed to init verification context");

                prop_assert!(
                    verify_result,
                    "Certificate chain verification must succeed: leaf cert signed by CA \
                     should validate against the CA trust bundle. SPIFFE ID: {}, billets: {:?}",
                    spiffe_id, billets
                );

                Ok(())
            })?;
        }
    }
}
