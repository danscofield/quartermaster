use async_trait::async_trait;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::config::identity::GcpSourceConfig;
use crate::domain::identity::{GcpIdentity, IdentityError};

use super::oidc::JwksProvider;

/// GCP identity token validator — verifies against Google's JWKS, extracts claims.
#[async_trait]
pub trait GcpValidator: Send + Sync {
    async fn validate(&self, token: &str) -> Result<GcpIdentity, IdentityError>;
}

/// The source ID used to retrieve Google's JWKS keys from the JwksProvider.
const GOOGLE_SOURCE_ID: &str = "google";

/// Full claims structure for a verified GCP identity token.
#[derive(Debug, Deserialize, Serialize)]
struct GcpTokenClaims {
    /// Issuer (e.g., "https://accounts.google.com")
    iss: Option<String>,
    /// Subject — the service account's unique numeric ID
    sub: Option<String>,
    /// Audience
    #[serde(default)]
    aud: AudienceClaim,
    /// Expiration time (Unix timestamp)
    exp: Option<u64>,
    /// Email (service account email)
    email: Option<String>,
    /// Nested Google-specific claims (compute_engine metadata)
    google: Option<GoogleClaims>,
}

/// Nested Google claims containing compute engine metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct GoogleClaims {
    compute_engine: Option<ComputeEngineClaims>,
}

/// Compute engine specific claims from a GCP identity token.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct ComputeEngineClaims {
    project_id: Option<String>,
    zone: Option<String>,
    #[allow(dead_code)]
    instance_id: Option<String>,
    #[allow(dead_code)]
    instance_name: Option<String>,
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

    fn to_string_repr(&self) -> String {
        match self {
            AudienceClaim::Single(s) => s.clone(),
            AudienceClaim::Multiple(v) => v.join(", "),
        }
    }
}

/// Default implementation of the GCP identity token validator.
/// Validates tokens against Google's JWKS and extracts GCP-specific claims.
pub struct DefaultGcpValidator<P: JwksProvider> {
    config: GcpSourceConfig,
    jwks_provider: P,
}

impl<P: JwksProvider> DefaultGcpValidator<P> {
    /// Create a new GCP validator with the given config and JWKS provider.
    pub fn new(config: GcpSourceConfig, jwks_provider: P) -> Self {
        Self {
            config,
            jwks_provider,
        }
    }

    /// Try to verify the token with the available keys.
    /// Tries all keys in order until one succeeds.
    fn try_verify_with_keys(
        token: &str,
        keys: &[DecodingKey],
        validation: &Validation,
    ) -> Result<TokenData<GcpTokenClaims>, IdentityError> {
        let mut last_error = None;

        for key in keys {
            match jsonwebtoken::decode::<GcpTokenClaims>(token, key, validation) {
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

#[async_trait]
impl<P: JwksProvider> GcpValidator for DefaultGcpValidator<P> {
    async fn validate(&self, token: &str) -> Result<GcpIdentity, IdentityError> {
        // Step 1: Decode JWT header to get algorithm
        let header = decode_header(token).map_err(|e| {
            IdentityError::InvalidSignature(format!("failed to decode JWT header: {}", e))
        })?;

        // Step 2: Determine the algorithm
        let algorithm = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            other => {
                return Err(IdentityError::InvalidSignature(format!(
                    "unsupported algorithm: {:?}",
                    other
                )));
            }
        };

        // Step 3: Get JWKS keys from provider using source_id "google"
        let keys = self.jwks_provider.get_keys(GOOGLE_SOURCE_ID).await?;

        if keys.is_empty() {
            return Err(IdentityError::KeysStale(GOOGLE_SOURCE_ID.to_string()));
        }

        // Step 4: Set up validation — verify exp, we handle audience manually
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        validation.validate_aud = false;
        // Google uses "https://accounts.google.com" as issuer
        validation.set_issuer(&["https://accounts.google.com"]);

        // Step 5: Verify signature and decode claims
        let token_data = Self::try_verify_with_keys(token, &keys, &validation)?;
        let claims = token_data.claims;

        // Step 6: Verify audience matches configured Quartermaster audience
        if !claims.aud.contains(&self.config.audience) {
            return Err(IdentityError::AudienceMismatch(claims.aud.to_string_repr()));
        }

        // Step 7: Extract required claims
        let unique_id = claims
            .sub
            .ok_or_else(|| IdentityError::MissingClaim("sub".to_string()))?;

        let email = claims
            .email
            .ok_or_else(|| IdentityError::MissingClaim("email".to_string()))?;

        // Extract project_id and zone from nested google.compute_engine claims
        let compute_engine = claims
            .google
            .and_then(|g| g.compute_engine);

        let project_id = compute_engine
            .as_ref()
            .and_then(|ce| ce.project_id.clone())
            .ok_or_else(|| {
                IdentityError::MissingClaim("google.compute_engine.project_id".to_string())
            })?;

        let zone = compute_engine
            .as_ref()
            .and_then(|ce| ce.zone.clone())
            .ok_or_else(|| {
                IdentityError::MissingClaim("google.compute_engine.zone".to_string())
            })?;

        // Step 8: Apply allowed_projects filter if configured
        if let Some(ref allowed_projects) = self.config.allowed_projects {
            if !allowed_projects.contains(&project_id) {
                return Err(IdentityError::NotAllowed(format!(
                    "GCP project '{}' is not in the allowed projects list",
                    project_id
                )));
            }
        }

        // Step 9: Return validated GcpIdentity
        Ok(GcpIdentity {
            project_id,
            email,
            zone,
            unique_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::HashMap;
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

    fn make_gcp_config() -> GcpSourceConfig {
        GcpSourceConfig {
            enabled: true,
            audience: "quartermaster.example.com".to_string(),
            allowed_projects: None,
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
        }
    }

    fn make_gcp_config_with_allowed_projects(projects: Vec<&str>) -> GcpSourceConfig {
        GcpSourceConfig {
            enabled: true,
            audience: "quartermaster.example.com".to_string(),
            allowed_projects: Some(projects.into_iter().map(|s| s.to_string()).collect()),
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
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

    /// Create a GCP identity token with standard claims.
    fn create_gcp_token(
        encoding_key: &EncodingKey,
        audience: &str,
        email: &str,
        sub: &str,
        project_id: &str,
        zone: &str,
        exp: u64,
    ) -> String {
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": sub,
            "aud": audience,
            "email": email,
            "exp": exp,
            "iat": chrono::Utc::now().timestamp() as u64,
            "google": {
                "compute_engine": {
                    "project_id": project_id,
                    "zone": zone,
                    "instance_id": "1234567890",
                    "instance_name": "my-instance"
                }
            }
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());

        encode(&header, &claims, encoding_key).expect("failed to encode token")
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
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "my-sa@my-project.iam.gserviceaccount.com",
            "112233445566778899",
            "my-project-123",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let identity = result.unwrap();
        assert_eq!(identity.project_id, "my-project-123");
        assert_eq!(
            identity.email,
            "my-sa@my-project.iam.gserviceaccount.com"
        );
        assert_eq!(identity.zone, "us-central1-a");
        assert_eq!(identity.unique_id, "112233445566778899");
    }

    #[tokio::test]
    async fn test_validate_audience_mismatch() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "wrong-audience.example.com",
            "my-sa@my-project.iam.gserviceaccount.com",
            "112233445566",
            "my-project",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::AudienceMismatch(_))));
    }

    #[tokio::test]
    async fn test_validate_invalid_signature() {
        let (encoding_key, _decoding_key) = generate_rsa_keys();
        let (_other_encoding_key, other_decoding_key) = generate_rsa_keys();

        let config = make_gcp_config();
        // Provide a different key than what signed the token
        let provider = TestJwksProvider::new().with_keys("google", vec![other_decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "my-sa@my-project.iam.gserviceaccount.com",
            "112233445566",
            "my-project",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn test_validate_token_expired() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "my-sa@my-project.iam.gserviceaccount.com",
            "112233445566",
            "my-project",
            "us-central1-a",
            past_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_err());
        // jsonwebtoken rejects expired tokens during signature verification
    }

    #[tokio::test]
    async fn test_validate_missing_email() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        // Create token without email claim
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "112233445566",
            "aud": "quartermaster.example.com",
            "exp": future_exp(),
            "iat": chrono::Utc::now().timestamp() as u64,
            "google": {
                "compute_engine": {
                    "project_id": "my-project",
                    "zone": "us-central1-a"
                }
            }
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(
            result,
            Err(IdentityError::MissingClaim(ref c)) if c == "email"
        ));
    }

    #[tokio::test]
    async fn test_validate_missing_sub() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        // Create token without sub claim
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "quartermaster.example.com",
            "email": "sa@project.iam.gserviceaccount.com",
            "exp": future_exp(),
            "iat": chrono::Utc::now().timestamp() as u64,
            "google": {
                "compute_engine": {
                    "project_id": "my-project",
                    "zone": "us-central1-a"
                }
            }
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(
            result,
            Err(IdentityError::MissingClaim(ref c)) if c == "sub"
        ));
    }

    #[tokio::test]
    async fn test_validate_missing_project_id() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        // Create token without project_id in google.compute_engine
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "112233445566",
            "aud": "quartermaster.example.com",
            "email": "sa@project.iam.gserviceaccount.com",
            "exp": future_exp(),
            "iat": chrono::Utc::now().timestamp() as u64,
            "google": {
                "compute_engine": {
                    "zone": "us-central1-a"
                }
            }
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(
            result,
            Err(IdentityError::MissingClaim(ref c)) if c == "google.compute_engine.project_id"
        ));
    }

    #[tokio::test]
    async fn test_validate_missing_zone() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        // Create token without zone in google.compute_engine
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "112233445566",
            "aud": "quartermaster.example.com",
            "email": "sa@project.iam.gserviceaccount.com",
            "exp": future_exp(),
            "iat": chrono::Utc::now().timestamp() as u64,
            "google": {
                "compute_engine": {
                    "project_id": "my-project"
                }
            }
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(
            result,
            Err(IdentityError::MissingClaim(ref c)) if c == "google.compute_engine.zone"
        ));
    }

    #[tokio::test]
    async fn test_validate_missing_google_claims() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        // Create token without any google claims
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "112233445566",
            "aud": "quartermaster.example.com",
            "email": "sa@project.iam.gserviceaccount.com",
            "exp": future_exp(),
            "iat": chrono::Utc::now().timestamp() as u64
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("google-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate(&token).await;
        assert!(matches!(
            result,
            Err(IdentityError::MissingClaim(ref c)) if c == "google.compute_engine.project_id"
        ));
    }

    #[tokio::test]
    async fn test_validate_allowed_projects_accepted() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config =
            make_gcp_config_with_allowed_projects(vec!["my-project-123", "other-project"]);
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "sa@my-project-123.iam.gserviceaccount.com",
            "112233445566",
            "my-project-123",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().project_id, "my-project-123");
    }

    #[tokio::test]
    async fn test_validate_allowed_projects_rejected() {
        let (encoding_key, decoding_key) = generate_rsa_keys();
        let config = make_gcp_config_with_allowed_projects(vec!["allowed-project-only"]);
        let provider = TestJwksProvider::new().with_keys("google", vec![decoding_key]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "sa@not-allowed.iam.gserviceaccount.com",
            "112233445566",
            "not-allowed-project",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::NotAllowed(_))));
    }

    #[tokio::test]
    async fn test_validate_no_keys_available() {
        let (encoding_key, _decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        // Provider returns empty keys
        let provider = TestJwksProvider::new().with_keys("google", vec![]);

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "sa@project.iam.gserviceaccount.com",
            "112233445566",
            "my-project",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_validate_keys_stale_no_source() {
        let (encoding_key, _decoding_key) = generate_rsa_keys();
        let config = make_gcp_config();
        // Provider has no "google" keys registered
        let provider = TestJwksProvider::new();

        let validator = DefaultGcpValidator::new(config, provider);

        let token = create_gcp_token(
            &encoding_key,
            "quartermaster.example.com",
            "sa@project.iam.gserviceaccount.com",
            "112233445566",
            "my-project",
            "us-central1-a",
            future_exp(),
        );

        let result = validator.validate(&token).await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_validate_invalid_token_format() {
        let config = make_gcp_config();
        let provider = TestJwksProvider::new().with_keys("google", vec![]);

        let validator = DefaultGcpValidator::new(config, provider);

        let result = validator.validate("not-a-jwt-token").await;
        assert!(matches!(result, Err(IdentityError::InvalidSignature(_))));
    }
}
