//! SVID validation logic — verifies SPIRE JWT-SVIDs and extracts claims.

use std::time::SystemTime;

use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

/// Claims represents the validated claims from a SPIRE JWT-SVID.
#[derive(Debug, Clone)]
pub struct Claims {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub environment: String,
    pub region: String,
    pub audience: Vec<String>,
    pub expires_at: SystemTime,
}

/// Errors that can occur during SVID validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvidError {
    /// JWT signature verification failed.
    SignatureInvalid(String),
    /// Token has expired.
    Expired,
    /// Issuer doesn't match configured trust domain.
    UnknownTrustDomain(String),
    /// Token audience doesn't include Quartermaster's issuer.
    InvalidAudience,
    /// Token couldn't be parsed.
    MalformedToken(String),
}

impl std::fmt::Display for SvidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SvidError::SignatureInvalid(msg) => write!(f, "signature invalid: {}", msg),
            SvidError::Expired => write!(f, "token expired"),
            SvidError::UnknownTrustDomain(domain) => {
                write!(f, "unknown trust domain: {}", domain)
            }
            SvidError::InvalidAudience => write!(f, "invalid audience"),
            SvidError::MalformedToken(msg) => write!(f, "malformed token: {}", msg),
        }
    }
}

impl std::error::Error for SvidError {}

/// Validator validates SPIRE JWT-SVIDs and extracts claims.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Validator: Send + Sync {
    /// Validate verifies the SVID signature, expiry, issuer, and audience.
    /// Returns parsed claims on success, or an error with category.
    async fn validate(&self, raw_token: &str) -> Result<Claims, SvidError>;
}

/// Raw JWT claims from a SPIRE JWT-SVID.
#[derive(Debug, Deserialize, Serialize)]
struct RawSvidClaims {
    /// Subject — the SPIFFE ID
    sub: String,
    /// Issuer — typically "spiffe://{trust_domain}" or a SPIRE-specific issuer
    #[serde(default)]
    iss: String,
    /// Audience
    #[serde(default)]
    aud: OneOrMany,
    /// Expiration time (unix timestamp)
    #[serde(default)]
    exp: u64,
    /// Issued at (unix timestamp)
    #[serde(default)]
    iat: u64,
}

/// Handles JWT `aud` claim which can be a single string or an array.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl Default for OneOrMany {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// A JWKS key entry used for finding the right decoding key by `kid`.
pub struct TrustBundleKey {
    pub kid: String,
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
}

impl std::fmt::Debug for TrustBundleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustBundleKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// SpireValidator validates JWT-SVIDs against a SPIRE trust bundle.
pub struct SpireValidator {
    /// The set of keys from the SPIRE trust bundle JWKS.
    trust_bundle_keys: Vec<TrustBundleKey>,
    /// The expected trust domain (e.g., "example.com").
    trust_domain: String,
    /// The Quartermaster issuer URL that must appear in the token's audience.
    quartermaster_issuer: String,
}

impl SpireValidator {
    /// Creates a new SpireValidator.
    ///
    /// # Arguments
    /// * `trust_bundle_keys` - Keys from the SPIRE trust bundle JWKS
    /// * `trust_domain` - The expected SPIFFE trust domain
    /// * `quartermaster_issuer` - The Quartermaster issuer URL (must appear in aud)
    pub fn new(
        trust_bundle_keys: Vec<TrustBundleKey>,
        trust_domain: String,
        quartermaster_issuer: String,
    ) -> Self {
        Self {
            trust_bundle_keys,
            trust_domain,
            quartermaster_issuer,
        }
    }

    /// Load trust bundle keys from a JWKS JSON string.
    pub fn parse_jwks(jwks_json: &str) -> Result<Vec<TrustBundleKey>, SvidError> {
        let jwks: serde_json::Value = serde_json::from_str(jwks_json).map_err(|e| {
            SvidError::MalformedToken(format!("failed to parse JWKS: {}", e))
        })?;

        let keys = jwks
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| {
                SvidError::MalformedToken("JWKS missing 'keys' array".to_string())
            })?;

        let mut bundle_keys = Vec::new();
        for key in keys {
            let kid = key
                .get("kid")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();

            let alg_str = key
                .get("alg")
                .and_then(|a| a.as_str())
                .unwrap_or("ES256");

            let algorithm = match alg_str {
                "ES256" => Algorithm::ES256,
                "ES384" => Algorithm::ES384,
                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,
                "PS256" => Algorithm::PS256,
                "PS384" => Algorithm::PS384,
                "PS512" => Algorithm::PS512,
                other => {
                    tracing::warn!("skipping JWKS key with unsupported algorithm: {}", other);
                    continue;
                }
            };

            let kty = key.get("kty").and_then(|k| k.as_str()).unwrap_or("");

            let decoding_key = match kty {
                "EC" => {
                    let x = key.get("x").and_then(|v| v.as_str()).unwrap_or("");
                    let y = key.get("y").and_then(|v| v.as_str()).unwrap_or("");
                    let crv = key.get("crv").and_then(|v| v.as_str()).unwrap_or("P-256");

                    // jsonwebtoken expects EC keys via components
                    DecodingKey::from_ec_components(x, y).map_err(|e| {
                        SvidError::MalformedToken(format!(
                            "failed to construct EC key (kid={}, crv={}): {}",
                            kid, crv, e
                        ))
                    })?
                }
                "RSA" => {
                    let n = key.get("n").and_then(|v| v.as_str()).unwrap_or("");
                    let e = key.get("e").and_then(|v| v.as_str()).unwrap_or("");
                    DecodingKey::from_rsa_components(n, e).map_err(|err| {
                        SvidError::MalformedToken(format!(
                            "failed to construct RSA key (kid={}): {}",
                            kid, err
                        ))
                    })?
                }
                other => {
                    tracing::warn!("skipping JWKS key with unsupported kty: {}", other);
                    continue;
                }
            };

            bundle_keys.push(TrustBundleKey {
                kid,
                algorithm,
                decoding_key,
            });
        }

        Ok(bundle_keys)
    }

    /// Find a key in the trust bundle by kid.
    fn find_key(&self, kid: &str) -> Option<&TrustBundleKey> {
        self.trust_bundle_keys.iter().find(|k| k.kid == kid)
    }

    /// Extract trust domain from a SPIFFE ID URI.
    /// e.g., "spiffe://example.com/ns/finance/workload/payments" → "example.com"
    fn extract_trust_domain(spiffe_id: &str) -> Option<&str> {
        spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next())
    }
}

#[async_trait::async_trait]
impl Validator for SpireValidator {
    async fn validate(&self, raw_token: &str) -> Result<Claims, SvidError> {
        // 1. Decode header (without verifying) to get kid
        let header = decode_header(raw_token).map_err(|e| {
            SvidError::MalformedToken(format!("failed to decode JWT header: {}", e))
        })?;

        let kid = header.kid.unwrap_or_default();

        // 2. Find matching key in trust bundle JWKS
        let bundle_key = self.find_key(&kid).ok_or_else(|| {
            SvidError::SignatureInvalid(format!(
                "no matching key found in trust bundle for kid '{}'",
                kid
            ))
        })?;

        // 3. Verify signature using the matching key
        // We set up validation to check exp but we'll also manually verify issuer and audience
        let mut validation = Validation::new(bundle_key.algorithm);
        // Disable default audience validation — we'll do it ourselves
        validation.validate_aud = false;
        // Enable exp validation
        validation.validate_exp = true;
        // Set required claims
        validation.set_required_spec_claims(&["sub", "exp"]);

        let token_data: TokenData<RawSvidClaims> =
            decode(raw_token, &bundle_key.decoding_key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => SvidError::Expired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature
                    | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                    | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_) => {
                        SvidError::SignatureInvalid(e.to_string())
                    }
                    _ => SvidError::MalformedToken(format!("JWT decode failed: {}", e)),
                }
            })?;

        let raw_claims = token_data.claims;

        // 4. Check exp is in future (already handled by jsonwebtoken Validation,
        //    but we also compute SystemTime for the Claims struct)
        let expires_at = SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(raw_claims.exp);

        // 5. Check iss starts with "spiffe://{trust_domain}"
        let expected_issuer_prefix = format!("spiffe://{}", self.trust_domain);
        if !raw_claims.iss.starts_with(&expected_issuer_prefix) {
            return Err(SvidError::UnknownTrustDomain(raw_claims.iss.clone()));
        }

        // 6. Check aud includes the Quartermaster issuer URL
        let audiences = raw_claims.aud.clone().into_vec();
        if !audiences.contains(&self.quartermaster_issuer) {
            return Err(SvidError::InvalidAudience);
        }

        // 7. Extract SPIFFE ID from sub claim
        let spiffe_id = raw_claims.sub.clone();

        // 8. Extract trust_domain from the SPIFFE ID URI
        let trust_domain = Self::extract_trust_domain(&spiffe_id)
            .unwrap_or(&self.trust_domain)
            .to_string();

        // Extract environment and region from the SPIFFE ID path segments if available.
        // Convention: spiffe://{domain}/{env}/{region}/...  or fall back to empty.
        let path_after_domain = spiffe_id
            .strip_prefix(&format!("spiffe://{}/", trust_domain))
            .unwrap_or("");
        let segments: Vec<&str> = path_after_domain.split('/').collect();

        // Use first path segment as environment hint, second as region hint.
        // These are best-effort; actual values may come from config or SPIRE selectors.
        let environment = segments.first().unwrap_or(&"").to_string();
        let region = segments.get(1).unwrap_or(&"").to_string();

        Ok(Claims {
            spiffe_id,
            trust_domain,
            environment,
            region,
            audience: audiences,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use ring::rand::SystemRandom;

    /// Generate a test EC P-256 key pair and return (encoding_key, decoding_key, kid).
    fn generate_test_ec_key() -> (EncodingKey, DecodingKey, String) {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();

        let encoding_key = EncodingKey::from_ec_pem(
            &pem_from_pkcs8(pkcs8_bytes.as_ref()),
        )
        .unwrap();

        // Extract the public key for DecodingKey
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();

        // EC public key in uncompressed form: 0x04 || x (32 bytes) || y (32 bytes)
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&public_key_bytes[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&public_key_bytes[33..65]);

        let decoding_key = DecodingKey::from_ec_components(&x, &y).unwrap();
        let kid = "test-kid-001".to_string();

        (encoding_key, decoding_key, kid)
    }

    /// Convert PKCS8 DER to PEM format for the encoding key.
    fn pem_from_pkcs8(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = Vec::new();
        pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        pem
    }

    use base64::Engine;

    fn make_valid_token(
        encoding_key: &EncodingKey,
        kid: &str,
        sub: &str,
        iss: &str,
        aud: &[&str],
        exp: u64,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());

        #[derive(Serialize)]
        struct TestClaims {
            sub: String,
            iss: String,
            aud: Vec<String>,
            exp: u64,
            iat: u64,
        }

        let claims = TestClaims {
            sub: sub.to_string(),
            iss: iss.to_string(),
            aud: aud.iter().map(|s| s.to_string()).collect(),
            exp,
            iat: exp - 300,
        };

        encode(&header, &claims, encoding_key).unwrap()
    }

    fn future_exp() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn past_exp() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600
    }

    fn make_validator(decoding_key: DecodingKey, kid: &str) -> SpireValidator {
        SpireValidator::new(
            vec![TrustBundleKey {
                kid: kid.to_string(),
                algorithm: Algorithm::ES256,
                decoding_key,
            }],
            "example.com".to_string(),
            "https://qm.example.com".to_string(),
        )
    }

    #[tokio::test]
    async fn test_valid_svid_accepted() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://example.com/ns/finance/workload/payments",
            "spiffe://example.com",
            &["https://qm.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let claims = result.unwrap();
        assert_eq!(
            claims.spiffe_id,
            "spiffe://example.com/ns/finance/workload/payments"
        );
        assert_eq!(claims.trust_domain, "example.com");
        assert_eq!(claims.environment, "ns");
        assert_eq!(claims.region, "finance");
        assert!(claims.audience.contains(&"https://qm.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_expired_token_rejected() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://example.com/workload/test",
            "spiffe://example.com",
            &["https://qm.example.com"],
            past_exp(),
        );

        let result = validator.validate(&token).await;
        assert_eq!(result.unwrap_err(), SvidError::Expired);
    }

    #[tokio::test]
    async fn test_unknown_trust_domain_rejected() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://evil.com/workload/test",
            "spiffe://evil.com",
            &["https://qm.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        match result.unwrap_err() {
            SvidError::UnknownTrustDomain(domain) => {
                assert_eq!(domain, "spiffe://evil.com");
            }
            other => panic!("expected UnknownTrustDomain, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_invalid_audience_rejected() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://example.com/workload/test",
            "spiffe://example.com",
            &["https://other-service.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert_eq!(result.unwrap_err(), SvidError::InvalidAudience);
    }

    #[tokio::test]
    async fn test_unknown_kid_rejected() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            "wrong-kid",
            "spiffe://example.com/workload/test",
            "spiffe://example.com",
            &["https://qm.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        match result.unwrap_err() {
            SvidError::SignatureInvalid(msg) => {
                assert!(msg.contains("no matching key"));
            }
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_malformed_token_rejected() {
        let (_, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let result = validator.validate("not.a.valid.jwt").await;
        match result.unwrap_err() {
            SvidError::MalformedToken(_) => {}
            other => panic!("expected MalformedToken, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_invalid_signature_rejected() {
        let (enc_key, _dec_key, kid) = generate_test_ec_key();
        // Create a validator with the correct kid but a DIFFERENT key
        let (_, other_dec_key, _) = generate_test_ec_key();
        let validator = make_validator(other_dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://example.com/workload/test",
            "spiffe://example.com",
            &["https://qm.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        match result.unwrap_err() {
            SvidError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_multiple_audiences_with_qm_issuer_accepted() {
        let (enc_key, dec_key, kid) = generate_test_ec_key();
        let validator = make_validator(dec_key, &kid);

        let token = make_valid_token(
            &enc_key,
            &kid,
            "spiffe://example.com/ns/prod/workload/api",
            "spiffe://example.com",
            &["https://qm.example.com", "https://other.example.com"],
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.audience.len(), 2);
    }

    #[test]
    fn test_parse_jwks_ec_key() {
        let jwks = r#"{
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-key-1",
                "alg": "ES256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }]
        }"#;

        let keys = SpireValidator::parse_jwks(jwks).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "test-key-1");
        assert_eq!(keys[0].algorithm, Algorithm::ES256);
    }

    #[test]
    fn test_parse_jwks_invalid_json() {
        let result = SpireValidator::parse_jwks("not json");
        assert!(matches!(result, Err(SvidError::MalformedToken(_))));
    }

    #[test]
    fn test_parse_jwks_missing_keys() {
        let result = SpireValidator::parse_jwks("{}");
        assert!(matches!(result, Err(SvidError::MalformedToken(_))));
    }

    #[test]
    fn test_extract_trust_domain() {
        assert_eq!(
            SpireValidator::extract_trust_domain("spiffe://example.com/ns/finance"),
            Some("example.com")
        );
        assert_eq!(
            SpireValidator::extract_trust_domain("spiffe://prod.internal/workload/api"),
            Some("prod.internal")
        );
        assert_eq!(SpireValidator::extract_trust_domain("not-a-spiffe-id"), None);
    }

    #[test]
    fn test_svid_error_display() {
        assert_eq!(
            format!("{}", SvidError::Expired),
            "token expired"
        );
        assert_eq!(
            format!("{}", SvidError::InvalidAudience),
            "invalid audience"
        );
        assert_eq!(
            format!("{}", SvidError::SignatureInvalid("bad sig".to_string())),
            "signature invalid: bad sig"
        );
        assert_eq!(
            format!("{}", SvidError::UnknownTrustDomain("evil.com".to_string())),
            "unknown trust domain: evil.com"
        );
        assert_eq!(
            format!("{}", SvidError::MalformedToken("parse error".to_string())),
            "malformed token: parse error"
        );
    }
}

/// Property-based tests for SVID validation correctness.
///
/// **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
#[cfg(test)]
mod proptest_svid {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use proptest::prelude::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde::Serialize;
    use std::time::SystemTime;

    /// Helper: Convert PKCS8 DER to PEM format.
    fn pem_from_pkcs8(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = Vec::new();
        pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        pem
    }

    /// Generate an EC P-256 key pair. Returns (encoding_key, decoding_key, x, y).
    fn generate_ec_key() -> (EncodingKey, DecodingKey, String, String) {
        use base64::Engine;
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let encoding_key = EncodingKey::from_ec_pem(&pem_from_pkcs8(pkcs8_bytes.as_ref())).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key_bytes[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key_bytes[33..65]);
        let decoding_key = DecodingKey::from_ec_components(&x, &y).unwrap();
        (encoding_key, decoding_key, x, y)
    }

    /// Current unix timestamp.
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// JWT claims for test token construction.
    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: Vec<String>,
        exp: u64,
        iat: u64,
    }

    /// Parameters that control one property test iteration.
    #[derive(Debug, Clone)]
    struct SvidTestCase {
        /// Whether the signing key is in the trust bundle (true = valid sig)
        key_in_bundle: bool,
        /// Whether the token is expired (true = expired)
        is_expired: bool,
        /// Whether the issuer matches the configured trust domain
        issuer_matches: bool,
        /// Whether the audience includes the Quartermaster issuer ID
        audience_includes_qm: bool,
        /// Random workload path segment
        workload_path: String,
        /// Extra audience entries
        extra_audiences: Vec<String>,
    }

    /// Strategy to generate test cases with controlled validity dimensions.
    fn svid_test_case_strategy() -> impl Strategy<Value = SvidTestCase> {
        (
            any::<bool>(),           // key_in_bundle
            any::<bool>(),           // is_expired
            any::<bool>(),           // issuer_matches
            any::<bool>(),           // audience_includes_qm
            "[a-z]{1,10}(/[a-z]{1,10}){0,3}", // workload_path
            prop::collection::vec("[a-z]{3,10}\\.[a-z]{2,5}\\.[a-z]{2,5}", 0..3), // extra_audiences
        )
            .prop_map(
                |(key_in_bundle, is_expired, issuer_matches, audience_includes_qm, workload_path, extra_audiences)| {
                    SvidTestCase {
                        key_in_bundle,
                        is_expired,
                        issuer_matches,
                        audience_includes_qm,
                        workload_path,
                        extra_audiences,
                    }
                },
            )
    }

    // Property 1: SVID Validation Correctness
    //
    // Generate random JWT payloads, signing keys (some in trust bundle, some not),
    // random expiry times, random issuers/audiences.
    //
    // Assert: validation accepts if and only if
    //   (valid sig AND not expired AND issuer matches AND audience includes issuer ID)
    //
    // **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_svid_validation_correctness(test_case in svid_test_case_strategy()) {
            // We use tokio runtime to run async validate
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let (result_is_ok, result_err) = rt.block_on(async {
                let trust_domain = "example.com";
                let qm_issuer = "https://qm.example.com";

                // Generate the "trusted" key (always in the bundle)
                let (trusted_enc_key, trusted_dec_key, _, _) = generate_ec_key();
                // Generate an "untrusted" key (never in the bundle)
                let (untrusted_enc_key, _, _, _) = generate_ec_key();

                let kid = "bundle-key-1";

                // Build the validator with the trusted key in its bundle
                let validator = SpireValidator::new(
                    vec![TrustBundleKey {
                        kid: kid.to_string(),
                        algorithm: Algorithm::ES256,
                        decoding_key: trusted_dec_key,
                    }],
                    trust_domain.to_string(),
                    qm_issuer.to_string(),
                );

                // Choose signing key based on test_case.key_in_bundle
                let signing_key = if test_case.key_in_bundle {
                    &trusted_enc_key
                } else {
                    &untrusted_enc_key
                };

                // Set expiry
                let exp = if test_case.is_expired {
                    now_secs() - 3600 // 1 hour in the past
                } else {
                    now_secs() + 3600 // 1 hour in the future
                };

                // Set issuer
                let issuer = if test_case.issuer_matches {
                    format!("spiffe://{}", trust_domain)
                } else {
                    "spiffe://evil.com".to_string()
                };

                // Build audience list
                let mut audiences: Vec<String> = test_case.extra_audiences.clone();
                if test_case.audience_includes_qm {
                    audiences.push(qm_issuer.to_string());
                }
                // Ensure at least one entry (avoid empty aud which may cause issues)
                if audiences.is_empty() {
                    audiences.push("https://other.example.com".to_string());
                }

                // Build the SPIFFE ID
                let spiffe_id = format!("spiffe://{}/{}", trust_domain, test_case.workload_path);

                // Construct and sign the JWT
                let mut header = Header::new(Algorithm::ES256);
                header.kid = Some(kid.to_string());

                let claims = TestClaims {
                    sub: spiffe_id,
                    iss: issuer,
                    aud: audiences,
                    exp,
                    iat: exp.saturating_sub(300),
                };

                let token = encode(&header, &claims, signing_key).unwrap();

                // Run validation
                let result = validator.validate(&token).await;
                let is_ok = result.is_ok();
                let err = result.err();
                (is_ok, err)
            });

            // Determine expected outcome
            let should_accept = test_case.key_in_bundle
                && !test_case.is_expired
                && test_case.issuer_matches
                && test_case.audience_includes_qm;

            if should_accept {
                prop_assert!(
                    result_is_ok,
                    "Expected validation to ACCEPT but got error: {:?}\nTest case: {:?}",
                    result_err,
                    test_case
                );
            } else {
                prop_assert!(
                    !result_is_ok,
                    "Expected validation to REJECT but it accepted.\nTest case: {:?}",
                    test_case
                );

                // Verify error category matches the first failing condition
                // (priority: signature > expiry > issuer > audience)
                let err = result_err.unwrap();
                if !test_case.key_in_bundle {
                    prop_assert!(
                        matches!(err, SvidError::SignatureInvalid(_)),
                        "Expected SignatureInvalid for key not in bundle, got {:?}",
                        err
                    );
                } else if test_case.is_expired {
                    prop_assert!(
                        matches!(err, SvidError::Expired),
                        "Expected Expired for expired token, got {:?}",
                        err
                    );
                } else if !test_case.issuer_matches {
                    prop_assert!(
                        matches!(err, SvidError::UnknownTrustDomain(_)),
                        "Expected UnknownTrustDomain for mismatched issuer, got {:?}",
                        err
                    );
                } else if !test_case.audience_includes_qm {
                    prop_assert!(
                        matches!(err, SvidError::InvalidAudience),
                        "Expected InvalidAudience when QM issuer not in aud, got {:?}",
                        err
                    );
                }
            }
        }
    }
}
