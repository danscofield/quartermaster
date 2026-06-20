//! KMS-backed certificate authority implementation.
//!
//! `KmsBackedAuthority` delegates signing key lifecycle management to a `KeyManager`
//! while reusing CSR verification and certificate construction logic from `LocalAuthority`.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa,
    KeyPair, KeyUsagePurpose, SanType, CertificateSigningRequestParams,
};
use time::OffsetDateTime;

use crate::keymanager::KeyManager;

use super::{
    generate_random_serial, Authority, CertError, CertIssueRequest, CertIssueResponse,
    LocalAuthority,
};

/// Certificate authority backed by a KMS-managed signing key.
///
/// The `KeyManager` handles key lifecycle (rotation, KMS attestation) while the
/// actual X.509 signing uses an `rcgen::KeyPair` extracted from the KMS-wrapped
/// CA private key material.
pub struct KmsBackedAuthority {
    /// Key manager for health/rotation awareness and future KMS operations.
    #[allow(dead_code)]
    key_manager: Arc<dyn KeyManager>,
    /// CA signing key pair (from KMS-wrapped storage) for rcgen cert signing.
    ca_key_pair: Arc<KeyPair>,
    /// PEM-encoded CA certificate.
    ca_cert_pem: Vec<u8>,
    /// Parsed CA certificate parameters for signing operations.
    ca_cert_params: Arc<CertificateParams>,
    /// Default certificate validity duration.
    ttl: Duration,
}

impl std::fmt::Debug for KmsBackedAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsBackedAuthority")
            .field("ttl", &self.ttl)
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .finish_non_exhaustive()
    }
}

impl KmsBackedAuthority {
    /// Creates a new `KmsBackedAuthority`.
    ///
    /// # Arguments
    /// * `key_manager` - Key manager for lifecycle/rotation awareness
    /// * `ca_key_pem` - PEM-encoded CA private key (from KMS-wrapped storage)
    /// * `ca_cert_pem` - PEM-encoded CA certificate
    /// * `ttl` - Default certificate validity duration
    pub fn new(
        key_manager: Arc<dyn KeyManager>,
        ca_key_pem: &str,
        ca_cert_pem: &str,
        ttl: Duration,
    ) -> Result<Self, CertError> {
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)
            .map_err(|e| CertError::CaNotReady(format!("failed to parse CA key: {}", e)))?;

        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| CertError::CaNotReady(format!("failed to parse CA cert: {}", e)))?;

        Ok(Self {
            key_manager,
            ca_key_pair: Arc::new(ca_key_pair),
            ca_cert_pem: ca_cert_pem.as_bytes().to_vec(),
            ca_cert_params: Arc::new(ca_cert_params),
            ttl,
        })
    }
}

#[async_trait::async_trait]
impl Authority for KmsBackedAuthority {
    async fn issue(&self, req: CertIssueRequest) -> Result<CertIssueResponse, CertError> {
        // 1. Verify CSR self-signature (reuse LocalAuthority's logic)
        LocalAuthority::verify_csr_signature(&req.csr_der)?;

        // 2. Parse CSR using rcgen to extract the public key
        let csr_der_ref: &[u8] = &req.csr_der;
        let csr_der_typed = csr_der_ref.into();
        let csr_params = CertificateSigningRequestParams::from_der(&csr_der_typed)
            .map_err(|e| CertError::InvalidCsr(format!("failed to parse CSR: {}", e)))?;

        // 3. Extract trust domain from SPIFFE ID
        let trust_domain = LocalAuthority::extract_trust_domain(&req.spiffe_id)?;

        // 4. Build certificate parameters - discard CSR Subject/SANs/extensions
        let mut params = CertificateParams::default();

        // Subject CN = SPIFFE ID
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &req.spiffe_id);
        params.distinguished_name = dn;

        // URI SANs: SPIFFE ID + qm-billet://{trust_domain}/{billet} for each billet
        let spiffe_ia5 = Ia5String::try_from(req.spiffe_id.as_str()).map_err(|e| {
            CertError::SigningFailed(format!("invalid SPIFFE ID for IA5String: {}", e))
        })?;
        let mut sans = vec![SanType::URI(spiffe_ia5)];
        for billet in &req.billets {
            let uri = format!("qm-billet://{}/{}", trust_domain, billet);
            let ia5 = Ia5String::try_from(uri.as_str()).map_err(|e| {
                CertError::SigningFailed(format!("invalid billet URI for IA5String: {}", e))
            })?;
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

        // 5. Sign with CA key (via KMS-wrapped key pair)
        let ca_params_clone = (*self.ca_cert_params).clone();
        let ca_cert = ca_params_clone.self_signed(&self.ca_key_pair).map_err(|e| {
            CertError::SigningFailed(format!("failed to create CA cert: {}", e))
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::Value;

    use crate::keymanager::{KeyHealth, KeyError, KeyManager};

    /// A minimal KeyManager implementation for testing.
    struct MockKeyManager {
        encoding_key: EncodingKey,
        header: Header,
        jwks: Value,
    }

    impl MockKeyManager {
        fn new() -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .expect("failed to generate test key");

            let b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pkcs8_doc.as_ref());
            let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str("-----END PRIVATE KEY-----\n");

            let encoding_key =
                EncodingKey::from_ec_pem(pem.as_bytes()).expect("failed to create encoding key");

            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("test-kms-kid".to_string());

            Self {
                encoding_key,
                header,
                jwks: serde_json::json!({"keys": []}),
            }
        }
    }

    #[async_trait]
    impl KeyManager for MockKeyManager {
        fn encoding_key(&self) -> &EncodingKey {
            &self.encoding_key
        }

        fn header(&self) -> &Header {
            &self.header
        }

        fn jwks(&self) -> &Value {
            &self.jwks
        }

        fn key_id(&self) -> &str {
            "test-kms-kid"
        }

        fn algorithm(&self) -> Algorithm {
            Algorithm::ES256
        }

        async fn health(&self) -> KeyHealth {
            KeyHealth::Healthy
        }

        async fn maybe_rotate(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    /// Generate a self-signed CA key pair and certificate for testing.
    fn generate_test_ca() -> (String, String) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test KMS CA");
        ca_params.distinguished_name = dn;
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        (ca_key.serialize_pem(), ca_cert.pem())
    }

    /// Generate a CSR (DER) for testing.
    fn generate_test_csr() -> Vec<u8> {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-workload");
        params.distinguished_name = dn;

        let csr = params.serialize_request(&key_pair).unwrap();
        csr.der().to_vec()
    }

    #[tokio::test]
    async fn test_kms_authority_issue_success() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let key_manager = Arc::new(MockKeyManager::new());

        let authority =
            KmsBackedAuthority::new(key_manager, &ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
                .expect("failed to create KmsBackedAuthority");

        let csr_der = generate_test_csr();

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

        // Chain should contain both certificates
        let chain_str = String::from_utf8(response.chain_pem.clone()).unwrap();
        let cert_count = chain_str.matches("BEGIN CERTIFICATE").count();
        assert_eq!(cert_count, 2, "chain should contain leaf + intermediate");
    }

    #[tokio::test]
    async fn test_kms_authority_invalid_csr() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let key_manager = Arc::new(MockKeyManager::new());

        let authority =
            KmsBackedAuthority::new(key_manager, &ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
                .expect("failed to create KmsBackedAuthority");

        let req = CertIssueRequest {
            csr_der: vec![0x30, 0x00],
            spiffe_id: "spiffe://example.org/workload/my-service".to_string(),
            billets: vec!["billing".to_string()],
        };

        let result = authority.issue(req).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::InvalidCsr(_) => {}
            other => panic!("expected InvalidCsr, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_kms_authority_chain_pem() {
        let (ca_key_pem, ca_cert_pem) = generate_test_ca();
        let key_manager = Arc::new(MockKeyManager::new());

        let authority =
            KmsBackedAuthority::new(key_manager, &ca_key_pem, &ca_cert_pem, Duration::from_secs(300))
                .expect("failed to create KmsBackedAuthority");

        let chain = authority.chain_pem();
        let chain_str = std::str::from_utf8(chain).unwrap();
        assert!(chain_str.contains("BEGIN CERTIFICATE"));
        assert_eq!(chain_str, ca_cert_pem);
    }

    #[test]
    fn test_kms_authority_invalid_ca_key() {
        let (_, ca_cert_pem) = generate_test_ca();
        let key_manager = Arc::new(MockKeyManager::new());

        let result =
            KmsBackedAuthority::new(key_manager, "not valid pem", &ca_cert_pem, Duration::from_secs(300));
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::CaNotReady(_) => {}
            other => panic!("expected CaNotReady, got: {:?}", other),
        }
    }

    #[test]
    fn test_kms_authority_invalid_ca_cert() {
        let (ca_key_pem, _) = generate_test_ca();
        let key_manager = Arc::new(MockKeyManager::new());

        let result =
            KmsBackedAuthority::new(key_manager, &ca_key_pem, "not valid cert", Duration::from_secs(300));
        assert!(result.is_err());
        match result.unwrap_err() {
            CertError::CaNotReady(_) => {}
            other => panic!("expected CaNotReady, got: {:?}", other),
        }
    }
}
