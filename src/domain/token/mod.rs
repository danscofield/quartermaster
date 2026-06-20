//! JWT construction and signing for Quartermaster tokens.

use std::sync::Arc;

use jsonwebtoken::encode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::signing::SigningManager;

/// Errors that can occur during token issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// JWT signing failed.
    SigningFailed(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed(msg) => write!(f, "signing failed: {msg}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// IssueRequest contains the parameters for JWT issuance.
#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub spiffe_id: String,
    pub audience: String,
    pub billets: Vec<String>,
}

/// IssueResponse contains the issued JWT and metadata.
#[derive(Debug, Clone)]
pub struct IssueResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    pub jti: String,
}

/// JWT claims for a Quartermaster token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (Quartermaster issuer URL)
    pub iss: String,
    /// Subject (workload SPIFFE ID)
    pub sub: String,
    /// Audience (single audience string)
    pub aud: String,
    /// Billet names the workload holds
    pub billets: Vec<String>,
    /// Issued-at timestamp (unix seconds)
    pub iat: u64,
    /// Expiration timestamp (unix seconds)
    pub exp: u64,
    /// JWT ID (UUID v4)
    pub jti: String,
}

/// Issuer creates signed Quartermaster JWTs.
#[async_trait::async_trait]
pub trait Issuer: Send + Sync {
    /// Issue creates a signed JWT with the given claims.
    async fn issue(&self, req: IssueRequest) -> Result<IssueResponse, TokenError>;
}

/// ES256-based token issuer implementation.
pub struct Es256Issuer {
    signing_manager: Arc<dyn SigningManager>,
    issuer_url: String,
    ttl_secs: u64,
}

impl Es256Issuer {
    /// Creates a new Es256Issuer.
    ///
    /// # Arguments
    /// * `signing_manager` - The signing key manager providing encoding key and header
    /// * `issuer_url` - The Quartermaster issuer URL (placed in `iss` claim)
    /// * `ttl_secs` - Token lifetime in seconds (used for `exp = iat + ttl`)
    pub fn new(
        signing_manager: Arc<dyn SigningManager>,
        issuer_url: String,
        ttl_secs: u64,
    ) -> Self {
        Self {
            signing_manager,
            issuer_url,
            ttl_secs,
        }
    }
}

#[async_trait::async_trait]
impl Issuer for Es256Issuer {
    async fn issue(&self, req: IssueRequest) -> Result<IssueResponse, TokenError> {
        let now = chrono::Utc::now().timestamp() as u64;
        let exp = now + self.ttl_secs;
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            iss: self.issuer_url.clone(),
            sub: req.spiffe_id,
            aud: req.audience,
            billets: req.billets,
            iat: now,
            exp,
            jti: jti.clone(),
        };

        let header = self.signing_manager.header().clone();
        let encoding_key = self.signing_manager.encoding_key();

        let token = encode(&header, &claims, encoding_key)
            .map_err(|e| TokenError::SigningFailed(e.to_string()))?;

        Ok(IssueResponse {
            access_token: token,
            issued_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: self.ttl_secs,
            jti,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use crate::signing::static_key::StaticKeyManager;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    /// Generate a test EC P-256 key pair and return the PKCS#8 PEM.
    fn generate_test_ec_key_pem() -> Vec<u8> {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("failed to generate test key");

        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_doc.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem.into_bytes()
    }

    fn test_signing_manager() -> Arc<dyn SigningManager> {
        let pem = generate_test_ec_key_pem();
        Arc::new(StaticKeyManager::from_pem(&pem).expect("should load key"))
    }

    #[tokio::test]
    async fn test_issue_returns_valid_jwt() {
        let manager = test_signing_manager();
        let issuer = Es256Issuer::new(
            manager.clone(),
            "https://qm.example.com".to_string(),
            300,
        );

        let req = IssueRequest {
            spiffe_id: "spiffe://example.com/workload".to_string(),
            audience: "https://api.example.com".to_string(),
            billets: vec!["payments".to_string(), "reporting".to_string()],
        };

        let resp = issuer.issue(req).await.unwrap();

        assert_eq!(resp.issued_token_type, "urn:ietf:params:oauth:token-type:jwt");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 300);
        assert!(!resp.access_token.is_empty());
        assert!(!resp.jti.is_empty());

        // Verify the token can be decoded
        let jwks = manager.jwks();
        let key_json = &jwks["keys"][0];
        let x = key_json["x"].as_str().unwrap();
        let y = key_json["y"].as_str().unwrap();

        // Build PEM from JWK components for decoding isn't straightforward,
        // so we just verify we can decode without signature check for claims
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["https://api.example.com"]);
        validation.set_issuer(&["https://qm.example.com"]);
        validation.insecure_disable_signature_validation();

        let token_data = jsonwebtoken::decode::<Claims>(
            &resp.access_token,
            &DecodingKey::from_ec_components(x, y).unwrap(),
            &validation,
        )
        .unwrap();

        assert_eq!(token_data.claims.iss, "https://qm.example.com");
        assert_eq!(token_data.claims.sub, "spiffe://example.com/workload");
        assert_eq!(token_data.claims.aud, "https://api.example.com");
        assert_eq!(token_data.claims.billets, vec!["payments", "reporting"]);
        assert_eq!(token_data.claims.exp - token_data.claims.iat, 300);
        assert_eq!(token_data.claims.jti, resp.jti);
    }

    #[tokio::test]
    async fn test_issue_jti_is_unique() {
        let manager = test_signing_manager();
        let issuer = Es256Issuer::new(
            manager,
            "https://qm.example.com".to_string(),
            300,
        );

        let req = IssueRequest {
            spiffe_id: "spiffe://example.com/workload".to_string(),
            audience: "https://api.example.com".to_string(),
            billets: vec!["payments".to_string()],
        };

        let resp1 = issuer.issue(req.clone()).await.unwrap();
        let resp2 = issuer.issue(req).await.unwrap();

        assert_ne!(resp1.jti, resp2.jti);
    }

    #[tokio::test]
    async fn test_issue_with_empty_billets() {
        let manager = test_signing_manager();
        let issuer = Es256Issuer::new(
            manager,
            "https://qm.example.com".to_string(),
            300,
        );

        let req = IssueRequest {
            spiffe_id: "spiffe://example.com/workload".to_string(),
            audience: "https://api.example.com".to_string(),
            billets: vec![],
        };

        let resp = issuer.issue(req).await.unwrap();
        assert!(!resp.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_issue_respects_configured_ttl() {
        let manager = test_signing_manager();
        let issuer = Es256Issuer::new(
            manager,
            "https://qm.example.com".to_string(),
            600,
        );

        let req = IssueRequest {
            spiffe_id: "spiffe://example.com/workload".to_string(),
            audience: "https://api.example.com".to_string(),
            billets: vec!["admin".to_string()],
        };

        let resp = issuer.issue(req).await.unwrap();
        assert_eq!(resp.expires_in, 600);
    }

    #[tokio::test]
    async fn test_jwt_header_has_kid() {
        let manager = test_signing_manager();
        let kid = manager.key_id().to_string();
        let issuer = Es256Issuer::new(
            manager,
            "https://qm.example.com".to_string(),
            300,
        );

        let req = IssueRequest {
            spiffe_id: "spiffe://example.com/workload".to_string(),
            audience: "https://api.example.com".to_string(),
            billets: vec!["payments".to_string()],
        };

        let resp = issuer.issue(req).await.unwrap();

        // Decode the header to check kid
        let header = jsonwebtoken::decode_header(&resp.access_token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(kid.as_str()));
        assert_eq!(header.alg, Algorithm::ES256);
    }

    // =========================================================================
    // Property-Based Tests
    // =========================================================================

    use proptest::prelude::*;

    /// Strategy for generating valid SPIFFE IDs.
    fn spiffe_id_strategy() -> impl Strategy<Value = String> {
        // Generate trust domain and path segments
        (
            "[a-z][a-z0-9]{1,10}\\.[a-z]{2,4}",
            prop::collection::vec("[a-z][a-z0-9\\-]{0,10}", 1..4),
        )
            .prop_map(|(domain, segments)| {
                format!("spiffe://{}/{}", domain, segments.join("/"))
            })
    }

    /// Strategy for generating valid audience strings.
    fn audience_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{1,8}\\.[a-z][a-z0-9]{1,8}\\.[a-z]{2,4}"
            .prop_map(|s| format!("https://{}", s))
    }

    /// Strategy for generating billet name sets.
    fn billets_strategy() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-z][a-z0-9\\-]{1,15}", 0..6)
    }

    /// Strategy for generating a TTL in seconds (between 60 and 3600).
    fn ttl_strategy() -> impl Strategy<Value = u64> {
        60u64..=3600u64
    }

    /// Strategy for generating an issuer URL.
    fn issuer_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{1,8}\\.[a-z]{2,4}"
            .prop_map(|domain| format!("https://{}", domain))
    }

    // Property 3: JWT ID Uniqueness
    //
    // Issue N tokens with same inputs, collect all jti values, assert all distinct.
    //
    // **Validates: Requirements 4.6**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_jwt_id_uniqueness(
            spiffe_id in spiffe_id_strategy(),
            audience in audience_strategy(),
            billets in billets_strategy(),
            n in 10u32..50u32,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let manager = test_signing_manager();
                let issuer = Es256Issuer::new(
                    manager,
                    "https://qm.example.com".to_string(),
                    300,
                );

                let mut jtis = std::collections::HashSet::new();

                for _ in 0..n {
                    let req = IssueRequest {
                        spiffe_id: spiffe_id.clone(),
                        audience: audience.clone(),
                        billets: billets.clone(),
                    };

                    let resp = issuer.issue(req).await.unwrap();
                    jtis.insert(resp.jti);
                }

                // All jti values must be distinct
                prop_assert_eq!(
                    jtis.len() as u32, n,
                    "All {} jti values must be distinct, but only {} unique values found",
                    n, jtis.len()
                );

                Ok(())
            })?;
        }
    }

    // Property 4: JWT Signature Verification Round-Trip
    //
    // Issue tokens, retrieve public key from SigningManager JWKS, verify signature succeeds,
    // kid in JWT header matches kid in JWKS.
    //
    // **Validates: Requirements 16.1, 16.2, 7.2, 7.3**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_jwt_signature_verification_round_trip(
            spiffe_id in spiffe_id_strategy(),
            audience in audience_strategy(),
            billets in billets_strategy(),
            ttl in ttl_strategy(),
            issuer_url in issuer_strategy(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let manager = test_signing_manager();

                // Get JWKS for verification
                let jwks = manager.jwks().clone();
                let keys = jwks["keys"].as_array().expect("JWKS should have keys array");
                prop_assert!(!keys.is_empty(), "JWKS must contain at least one key");

                let jwk = &keys[0];
                let jwk_kid = jwk["kid"].as_str().expect("JWK should have kid");
                let jwk_alg = jwk["alg"].as_str().expect("JWK should have alg");
                let x = jwk["x"].as_str().expect("JWK should have x");
                let y = jwk["y"].as_str().expect("JWK should have y");

                // Issue a token
                let issuer = Es256Issuer::new(
                    manager.clone(),
                    issuer_url.clone(),
                    ttl,
                );

                let req = IssueRequest {
                    spiffe_id: spiffe_id.clone(),
                    audience: audience.clone(),
                    billets: billets.clone(),
                };

                let resp = issuer.issue(req).await.unwrap();

                // Decode JWT header to get kid
                let header = jsonwebtoken::decode_header(&resp.access_token)
                    .expect("JWT header should be decodable");

                let jwt_kid = header.kid.as_deref()
                    .expect("JWT header must have kid");

                // Assert: kid in JWT header matches kid in JWKS
                prop_assert_eq!(
                    jwt_kid, jwk_kid,
                    "kid in JWT header must match kid in JWKS"
                );

                // Assert: algorithm matches
                prop_assert_eq!(
                    format!("{:?}", header.alg), "ES256",
                    "JWT algorithm must be ES256"
                );
                prop_assert_eq!(
                    jwk_alg, "ES256",
                    "JWK algorithm must be ES256"
                );

                // Verify signature using the public key from JWKS
                let decoding_key = DecodingKey::from_ec_components(x, y)
                    .expect("should create decoding key from JWKS components");

                let mut validation = Validation::new(Algorithm::ES256);
                validation.set_audience(&[&audience]);
                validation.set_issuer(&[&issuer_url]);

                let token_data = jsonwebtoken::decode::<Claims>(
                    &resp.access_token,
                    &decoding_key,
                    &validation,
                );

                // Assert: signature verification succeeds
                prop_assert!(
                    token_data.is_ok(),
                    "JWT signature verification using JWKS public key must succeed, got error: {:?}",
                    token_data.err()
                );

                let claims = token_data.unwrap().claims;

                // Additional sanity: verify claims are intact after signature verification
                prop_assert_eq!(
                    &claims.sub, &spiffe_id,
                    "sub claim must be preserved after signature verification"
                );
                prop_assert_eq!(
                    &claims.iss, &issuer_url,
                    "iss claim must be preserved after signature verification"
                );

                Ok(())
            })?;
        }
    }

    // Property 2: JWT Issuance Round-Trip
    //
    // Generate random SPIFFE IDs, audiences, billet sets; issue then parse.
    //
    // Assert: iss == config issuer, sub == input SPIFFE ID, aud == single audience,
    //         billets == input set, exp - iat == TTL
    //
    // **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 10.1, 10.2, 10.3, 14.6**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_jwt_issuance_round_trip(
            spiffe_id in spiffe_id_strategy(),
            audience in audience_strategy(),
            billets in billets_strategy(),
            ttl in ttl_strategy(),
            issuer_url in issuer_strategy(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let manager = test_signing_manager();

                // Get JWKS for decoding - clone the values before moving manager
                let jwks = manager.jwks().clone();
                let key_json = &jwks["keys"][0];
                let x = key_json["x"].as_str().unwrap().to_string();
                let y = key_json["y"].as_str().unwrap().to_string();

                let issuer = Es256Issuer::new(
                    manager,
                    issuer_url.clone(),
                    ttl,
                );

                let req = IssueRequest {
                    spiffe_id: spiffe_id.clone(),
                    audience: audience.clone(),
                    billets: billets.clone(),
                };

                let resp = issuer.issue(req).await.unwrap();

                // Parse the token back without signature validation first,
                // then verify claims match
                let mut validation = Validation::new(Algorithm::ES256);
                validation.set_audience(&[&audience]);
                validation.set_issuer(&[&issuer_url]);
                // Disable signature validation for claims extraction
                // (Property 4 tests signature separately)
                validation.insecure_disable_signature_validation();

                let token_data = jsonwebtoken::decode::<Claims>(
                    &resp.access_token,
                    &DecodingKey::from_ec_components(&x, &y).unwrap(),
                    &validation,
                )
                .unwrap();

                let claims = token_data.claims;

                // Assert: iss == config issuer
                prop_assert_eq!(
                    &claims.iss, &issuer_url,
                    "iss claim must equal configured issuer URL"
                );

                // Assert: sub == input SPIFFE ID
                prop_assert_eq!(
                    &claims.sub, &spiffe_id,
                    "sub claim must equal input SPIFFE ID"
                );

                // Assert: aud == single audience (not wildcard, not multiple)
                prop_assert_eq!(
                    &claims.aud, &audience,
                    "aud claim must be exactly the single requested audience"
                );

                // Assert: billets == input set
                prop_assert_eq!(
                    &claims.billets, &billets,
                    "billets claim must equal input billet set"
                );

                // Assert: exp - iat == TTL
                let actual_ttl = claims.exp - claims.iat;
                prop_assert_eq!(
                    actual_ttl, ttl,
                    "exp - iat must equal configured TTL"
                );

                // Assert: expires_in in response equals TTL
                prop_assert_eq!(
                    resp.expires_in, ttl,
                    "expires_in in response must equal configured TTL"
                );

                // Assert: jti is non-empty (UUID)
                prop_assert!(
                    !claims.jti.is_empty(),
                    "jti must be non-empty"
                );

                // Assert: jti matches response jti
                prop_assert_eq!(
                    &claims.jti, &resp.jti,
                    "jti in claims must match jti in response"
                );

                Ok(())
            })?;
        }
    }
}
