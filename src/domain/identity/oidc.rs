use std::collections::HashMap;

use async_trait::async_trait;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::config::identity::OidcSourceConfig;
use crate::domain::identity::{IdentityError, OidcIdentity};

/// Provider of JWKS decoding keys for a given OIDC source.
/// The JwksManager (implemented in a later task) will fulfill this trait.
#[async_trait]
pub trait JwksProvider: Send + Sync {
    /// Get the decoding keys for a given source identified by its prefix.
    async fn get_keys(&self, source_id: &str) -> Result<Vec<DecodingKey>, IdentityError>;
}

/// OIDC IdP token validator — identifies the IdP by issuer, verifies signature via cached JWKS.
#[async_trait]
pub trait OidcValidator: Send + Sync {
    async fn validate(&self, token: &str) -> Result<OidcIdentity, IdentityError>;
}

/// Raw JWT claims structure used for initial unverified decode (to extract `iss`).
#[derive(Debug, Deserialize)]
struct UnverifiedClaims {
    iss: Option<String>,
}

/// Full claims structure for verified token decode.
#[derive(Debug, Deserialize, Serialize)]
struct OidcTokenClaims {
    /// Issuer
    iss: Option<String>,
    /// Subject
    sub: Option<String>,
    /// Audience (can be a single string or array)
    #[serde(default)]
    aud: AudienceClaim,
    /// Expiration time (Unix timestamp)
    exp: Option<u64>,
    /// Email claim
    email: Option<String>,
    /// Catch-all for additional claims we might need to extract
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// The `aud` claim can be either a single string or an array of strings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for AudienceClaim {
    fn default() -> Self {
        AudienceClaim::Multiple(vec![])
    }
}

impl AudienceClaim {
    fn contains(&self, target: &str) -> bool {
        match self {
            AudienceClaim::Single(s) => s == target,
            AudienceClaim::Multiple(v) => v.iter().any(|s| s == target),
        }
    }
}

/// Default implementation of the OIDC validator.
/// Validates tokens against configured OIDC identity providers.
pub struct DefaultOidcValidator<P: JwksProvider> {
    configs: Vec<OidcSourceConfig>,
    jwks_provider: P,
}

impl<P: JwksProvider> DefaultOidcValidator<P> {
    /// Create a new OIDC validator with the given configs and JWKS provider.
    pub fn new(configs: Vec<OidcSourceConfig>, jwks_provider: P) -> Self {
        Self {
            configs,
            jwks_provider,
        }
    }

    /// Find the OIDC source config that matches the given issuer URL.
    fn find_source_by_issuer(&self, issuer: &str) -> Option<&OidcSourceConfig> {
        self.configs.iter().find(|c| c.issuer == issuer)
    }

    /// Extract claim values from the token claims for a given claim name.
    /// Supports string claims (returned as single-element vec) and array-of-string claims.
    fn extract_claim_values(
        claims: &HashMap<String, serde_json::Value>,
        claim_name: &str,
    ) -> Vec<String> {
        match claims.get(claim_name) {
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }
}

#[async_trait]
impl<P: JwksProvider> OidcValidator for DefaultOidcValidator<P> {
    async fn validate(&self, token: &str) -> Result<OidcIdentity, IdentityError> {
        // Step 1: Decode header to get the key ID (kid) and algorithm
        let header = decode_header(token).map_err(|e| {
            IdentityError::InvalidSignature(format!("failed to decode JWT header: {}", e))
        })?;

        let kid = header.kid.clone();

        // Step 2: Decode payload without verification to extract issuer
        let mut insecure_validation = Validation::default();
        insecure_validation.insecure_disable_signature_validation();
        insecure_validation.validate_exp = false;
        insecure_validation.validate_aud = false;

        let unverified: TokenData<UnverifiedClaims> =
            jsonwebtoken::decode(token, &DecodingKey::from_secret(b""), &insecure_validation)
                .map_err(|e| {
                    IdentityError::InvalidSignature(format!(
                        "failed to decode token claims: {}",
                        e
                    ))
                })?;

        let issuer = unverified
            .claims
            .iss
            .ok_or_else(|| IdentityError::MissingClaim("iss".to_string()))?;

        // Step 3: Match issuer against configured sources
        let source = self
            .find_source_by_issuer(&issuer)
            .ok_or_else(|| IdentityError::IssuerNotFound(issuer.clone()))?;

        // Step 4: Get JWKS keys for this source
        let keys = self.jwks_provider.get_keys(&source.prefix).await?;

        if keys.is_empty() {
            return Err(IdentityError::KeysStale(source.prefix.clone()));
        }

        // Step 5: Find the matching key by kid (if provided) or try all keys
        let algorithm = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
            other => {
                return Err(IdentityError::InvalidSignature(format!(
                    "unsupported algorithm: {:?}",
                    other
                )));
            }
        };

        // Set up validation: verify exp, verify aud against configured client_ids
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        // We handle audience validation manually after decode so we can check
        // against *any* of the configured client_ids
        validation.validate_aud = false;
        validation.set_issuer(&[&issuer]);

        // Step 6: Try to verify the token signature with available keys
        let token_data = Self::try_verify_with_keys(token, &keys, &kid, &validation)?;

        let claims = token_data.claims;

        // Step 7: Verify audience - token's aud must contain at least one of client_ids
        let audience_matches = source.client_ids.iter().any(|cid| claims.aud.contains(cid));
        if !audience_matches {
            let aud_str = match &claims.aud {
                AudienceClaim::Single(s) => s.clone(),
                AudienceClaim::Multiple(v) => v.join(", "),
            };
            return Err(IdentityError::AudienceMismatch(aud_str));
        }

        // Step 8: Extract required claims
        let email = claims
            .email
            .ok_or_else(|| IdentityError::MissingClaim("email".to_string()))?;

        let subject = claims
            .sub
            .ok_or_else(|| IdentityError::MissingClaim("sub".to_string()))?;

        // Step 9: Extract all configured implicit claim values
        let mut extracted_claims: HashMap<String, Vec<String>> = HashMap::new();
        for implicit in &source.implicit_claims {
            let values = Self::extract_claim_values(&claims.extra, &implicit.claim);
            if !values.is_empty() {
                extracted_claims.insert(implicit.claim.clone(), values);
            }
        }

        // Step 10: Return the validated identity
        Ok(OidcIdentity {
            email,
            idp_prefix: source.prefix.clone(),
            claims: extracted_claims,
            subject,
        })
    }
}

impl<P: JwksProvider> DefaultOidcValidator<P> {
    /// Try to verify the token with the available keys.
    /// If a `kid` is provided in the header, we could use it to select the right key,
    /// but since `DecodingKey` doesn't expose `kid`, we try all keys in order.
    fn try_verify_with_keys(
        token: &str,
        keys: &[DecodingKey],
        _kid: &Option<String>,
        validation: &Validation,
    ) -> Result<TokenData<OidcTokenClaims>, IdentityError> {
        let mut last_error = None;

        for key in keys {
            match jsonwebtoken::decode::<OidcTokenClaims>(token, key, validation) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(IdentityError::InvalidSignature(
            last_error
                .map(|e| format!("no matching key found: {}", e))
                .unwrap_or_else(|| "no keys available".to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::Duration;

    /// A test JWKS provider that returns pre-configured keys.
    struct TestJwksProvider {
        keys: HashMap<String, Vec<DecodingKey>>,
    }

    impl TestJwksProvider {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }

        fn with_keys(mut self, source_id: &str, keys: Vec<DecodingKey>) -> Self {
            self.keys.insert(source_id.to_string(), keys);
            self
        }
    }

    #[async_trait]
    impl JwksProvider for TestJwksProvider {
        async fn get_keys(&self, source_id: &str) -> Result<Vec<DecodingKey>, IdentityError> {
            self.keys
                .get(source_id)
                .cloned()
                .ok_or_else(|| IdentityError::KeysStale(source_id.to_string()))
        }
    }

    fn make_oidc_config(prefix: &str, issuer: &str, client_ids: Vec<&str>) -> OidcSourceConfig {
        use crate::config::identity::ImplicitClaimConfig;
        OidcSourceConfig {
            prefix: prefix.to_string(),
            issuer: issuer.to_string(),
            client_ids: client_ids.into_iter().map(|s| s.to_string()).collect(),
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
            implicit_claims: vec![ImplicitClaimConfig {
                claim: "groups".to_string(),
                billet_prefix: format!("{}-group", prefix),
                in_tokens: true,
            }],
        }
    }

    /// Generate an RSA key pair for testing and return (encoding_key, decoding_key).
    fn generate_rsa_keys() -> (EncodingKey, DecodingKey) {
        use openssl::rsa::Rsa;

        let rsa = Rsa::generate(2048).expect("failed to generate RSA key");

        let private_pem = rsa
            .private_key_to_pem()
            .expect("failed to export private key PEM");
        let public_pem = rsa
            .public_key_to_pem()
            .expect("failed to export public key PEM");

        let encoding_key =
            EncodingKey::from_rsa_pem(&private_pem).expect("failed to create encoding key");
        let decoding_key =
            DecodingKey::from_rsa_pem(&public_pem).expect("failed to create decoding key");

        (encoding_key, decoding_key)
    }

    fn create_test_token(
        encoding_key: &EncodingKey,
        issuer: &str,
        audience: &str,
        email: &str,
        subject: &str,
        exp: u64,
        groups: Option<Vec<&str>>,
    ) -> String {
        let mut claims_map = serde_json::Map::new();
        claims_map.insert("iss".into(), serde_json::Value::String(issuer.to_string()));
        claims_map.insert("sub".into(), serde_json::Value::String(subject.to_string()));
        claims_map.insert("aud".into(), serde_json::Value::String(audience.to_string()));
        claims_map.insert("exp".into(), serde_json::json!(exp));
        claims_map.insert(
            "iat".into(),
            serde_json::json!(chrono::Utc::now().timestamp() as u64),
        );
        claims_map.insert(
            "email".into(),
            serde_json::Value::String(email.to_string()),
        );

        if let Some(groups) = groups {
            claims_map.insert(
                "groups".into(),
                serde_json::Value::Array(
                    groups
                        .into_iter()
                        .map(|g| serde_json::Value::String(g.to_string()))
                        .collect(),
                ),
            );
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        encode(
            &header,
            &serde_json::Value::Object(claims_map),
            encoding_key,
        )
        .expect("failed to encode token")
    }

    fn future_exp() -> u64 {
        (chrono::Utc::now().timestamp() + 3600) as u64
    }

    fn past_exp() -> u64 {
        (chrono::Utc::now().timestamp() - 3600) as u64
    }

    #[tokio::test]
    async fn test_validate_success() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "client-1",
            "alice@example.com",
            "auth0|12345",
            future_exp(),
            Some(vec!["engineering", "billing"]),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let identity = result.unwrap();
        assert_eq!(identity.email, "alice@example.com");
        assert_eq!(identity.idp_prefix, "okta");
        assert_eq!(identity.subject, "auth0|12345");
        assert_eq!(
            identity.claims.get("groups").unwrap(),
            &vec!["engineering".to_string(), "billing".to_string()]
        );
    }

    #[tokio::test]
    async fn test_validate_issuer_not_found() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        let token = create_test_token(
            &encoding_key,
            "https://evil.example.com",
            "client-1",
            "alice@example.com",
            "sub-1",
            future_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::IssuerNotFound(_))));
    }

    #[tokio::test]
    async fn test_validate_invalid_signature() {
        let (encoding_key, _decoding_key) = generate_rsa_keys();
        let (_other_encoding_key, other_decoding_key) = generate_rsa_keys();

        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        // Provide a different key than what signed the token
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![other_decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "client-1",
            "alice@example.com",
            "sub-1",
            future_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn test_validate_audience_mismatch() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        // Token has wrong audience
        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "wrong-client",
            "alice@example.com",
            "sub-1",
            future_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::AudienceMismatch(_))));
    }

    #[tokio::test]
    async fn test_validate_token_expired() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "client-1",
            "alice@example.com",
            "sub-1",
            past_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        // The jsonwebtoken crate returns an error for expired tokens during decode
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_missing_email() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        // Create token without email claim
        let mut claims_map = serde_json::Map::new();
        claims_map.insert(
            "iss".into(),
            serde_json::Value::String("https://okta.example.com".to_string()),
        );
        claims_map.insert(
            "sub".into(),
            serde_json::Value::String("sub-1".to_string()),
        );
        claims_map.insert(
            "aud".into(),
            serde_json::Value::String("client-1".to_string()),
        );
        claims_map.insert("exp".into(), serde_json::json!(future_exp()));
        claims_map.insert(
            "iat".into(),
            serde_json::json!(chrono::Utc::now().timestamp() as u64),
        );
        // No email!

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let token = encode(
            &header,
            &serde_json::Value::Object(claims_map),
            &encoding_key,
        )
        .unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::MissingClaim(ref c)) if c == "email"));
    }

    #[tokio::test]
    async fn test_validate_multiple_client_ids() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_oidc_config(
            "okta",
            "https://okta.example.com",
            vec!["client-1", "client-2", "client-3"],
        );
        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        // Token has aud=client-2 which is in the allowed list
        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "client-2",
            "bob@example.com",
            "sub-2",
            future_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().email, "bob@example.com");
    }

    #[tokio::test]
    async fn test_validate_multiple_sources() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let okta_config = make_oidc_config("okta", "https://okta.example.com", vec!["okta-client"]);
        let azure_config = make_oidc_config(
            "azuread",
            "https://login.microsoft.com/tenant/v2.0",
            vec!["azure-client"],
        );

        let provider = TestJwksProvider::new()
            .with_keys("okta", vec![decoding_key.clone()])
            .with_keys("azuread", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![okta_config, azure_config], provider);

        // Token from Azure
        let token = create_test_token(
            &encoding_key,
            "https://login.microsoft.com/tenant/v2.0",
            "azure-client",
            "carol@corp.com",
            "azure-sub-1",
            future_exp(),
            Some(vec!["admins"]),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.idp_prefix, "azuread");
        assert_eq!(identity.email, "carol@corp.com");
    }

    #[tokio::test]
    async fn test_validate_no_keys_available() {
        let (encoding_key, _decoding_key) = generate_rsa_keys();
        let config = make_oidc_config("okta", "https://okta.example.com", vec!["client-1"]);
        // Provider returns empty keys
        let provider = TestJwksProvider::new().with_keys("okta", vec![]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        let token = create_test_token(
            &encoding_key,
            "https://okta.example.com",
            "client-1",
            "alice@example.com",
            "sub-1",
            future_exp(),
            None,
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_extract_multiple_claims() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        use crate::config::identity::ImplicitClaimConfig;

        let config = OidcSourceConfig {
            prefix: "okta".to_string(),
            issuer: "https://okta.example.com".to_string(),
            client_ids: vec!["client-1".to_string()],
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
            implicit_claims: vec![
                ImplicitClaimConfig {
                    claim: "groups".to_string(),
                    billet_prefix: "okta-group".to_string(),
                    in_tokens: true,
                },
                ImplicitClaimConfig {
                    claim: "roles".to_string(),
                    billet_prefix: "okta-role".to_string(),
                    in_tokens: false,
                },
            ],
        };

        let provider =
            TestJwksProvider::new().with_keys("okta", vec![decoding_key]);

        let validator = DefaultOidcValidator::new(vec![config], provider);

        // Create token with both groups and roles claims
        let mut claims_map = serde_json::Map::new();
        claims_map.insert(
            "iss".into(),
            serde_json::Value::String("https://okta.example.com".to_string()),
        );
        claims_map.insert(
            "sub".into(),
            serde_json::Value::String("sub-1".to_string()),
        );
        claims_map.insert(
            "aud".into(),
            serde_json::Value::String("client-1".to_string()),
        );
        claims_map.insert("exp".into(), serde_json::json!(future_exp()));
        claims_map.insert(
            "iat".into(),
            serde_json::json!(chrono::Utc::now().timestamp() as u64),
        );
        claims_map.insert(
            "email".into(),
            serde_json::Value::String("alice@example.com".to_string()),
        );
        claims_map.insert(
            "groups".into(),
            serde_json::json!(["engineering", "billing"]),
        );
        claims_map.insert("roles".into(), serde_json::json!(["admin", "viewer"]));

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let token = encode(
            &header,
            &serde_json::Value::Object(claims_map),
            &encoding_key,
        )
        .unwrap();

        let result = validator.validate(&token).await;
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(
            identity.claims.get("groups").unwrap(),
            &vec!["engineering".to_string(), "billing".to_string()]
        );
        assert_eq!(
            identity.claims.get("roles").unwrap(),
            &vec!["admin".to_string(), "viewer".to_string()]
        );
    }
}
