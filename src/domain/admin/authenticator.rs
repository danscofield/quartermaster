//! Control plane JWT auth + local Cedar admin authorization.
//!
//! Verifies Quartermaster-issued JWTs and evaluates Cedar policies
//! to authorize admin actions on the control plane.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::cedar::{AdminAuthzRequest, CommonContext, LocalAuthorizer};
use crate::domain::token::Claims;
use crate::signing::SigningManager;

/// Errors that can occur during admin authentication and authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthError {
    /// No Authorization header or not in Bearer format (401).
    MissingCredentials,
    /// JWT signature failed or token is malformed (401).
    InvalidToken(String),
    /// JWT has expired (401).
    TokenExpired,
    /// Cedar evaluation denied for all billets (403).
    InsufficientPrivileges,
}

impl std::fmt::Display for AdminAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredentials => write!(f, "missing or malformed credentials"),
            Self::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::InsufficientPrivileges => write!(f, "insufficient privileges"),
        }
    }
}

impl std::error::Error for AdminAuthError {}

/// Authenticator verifies admin JWT tokens and evaluates Cedar authorization.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate the caller from the Authorization header value.
    ///
    /// Returns the authenticated SPIFFE ID (sub claim) on success,
    /// or an appropriate error indicating 401 or 403.
    async fn authenticate(
        &self,
        auth_header: &str,
        action: &str,
        resource: &str,
    ) -> Result<String, AdminAuthError>;
}

/// Implementation of Authenticator that verifies Quartermaster-issued JWTs
/// against the local JWKS and evaluates Cedar policies for admin authorization.
pub struct AdminAuthenticatorImpl {
    signing_manager: Arc<dyn SigningManager>,
    local_authorizer: Arc<dyn LocalAuthorizer>,
    issuer_url: String,
}

impl AdminAuthenticatorImpl {
    /// Creates a new AdminAuthenticatorImpl.
    ///
    /// # Arguments
    /// * `signing_manager` - Provides JWKS for JWT verification
    /// * `local_authorizer` - Cedar policy evaluator for admin authorization
    /// * `issuer_url` - Expected issuer URL in the JWT `iss` claim
    pub fn new(
        signing_manager: Arc<dyn SigningManager>,
        local_authorizer: Arc<dyn LocalAuthorizer>,
        issuer_url: String,
    ) -> Self {
        Self {
            signing_manager,
            local_authorizer,
            issuer_url,
        }
    }

    /// Extract the Bearer token from an Authorization header value.
    fn extract_bearer_token(auth_header: &str) -> Result<&str, AdminAuthError> {
        let trimmed = auth_header.trim();
        if trimmed.len() < 8 {
            return Err(AdminAuthError::MissingCredentials);
        }
        let prefix = &trimmed[..7];
        if !prefix.eq_ignore_ascii_case("bearer ") {
            return Err(AdminAuthError::MissingCredentials);
        }
        let token = trimmed[7..].trim();
        if token.is_empty() {
            return Err(AdminAuthError::MissingCredentials);
        }
        Ok(token)
    }

    /// Build a DecodingKey from the JWKS x,y components for ES256 verification.
    fn decoding_key_from_jwks(&self, kid: &str) -> Result<DecodingKey, AdminAuthError> {
        let jwks = self.signing_manager.jwks();
        let keys = jwks["keys"]
            .as_array()
            .ok_or_else(|| AdminAuthError::InvalidToken("JWKS missing keys array".to_string()))?;

        for key in keys {
            if key["kid"].as_str() == Some(kid) {
                let x = key["x"].as_str().ok_or_else(|| {
                    AdminAuthError::InvalidToken("JWKS key missing x component".to_string())
                })?;
                let y = key["y"].as_str().ok_or_else(|| {
                    AdminAuthError::InvalidToken("JWKS key missing y component".to_string())
                })?;

                return DecodingKey::from_ec_components(x, y).map_err(|e| {
                    AdminAuthError::InvalidToken(format!("failed to build decoding key: {e}"))
                });
            }
        }

        Err(AdminAuthError::InvalidToken(format!(
            "no key found with kid: {kid}"
        )))
    }
}

#[async_trait::async_trait]
impl Authenticator for AdminAuthenticatorImpl {
    async fn authenticate(
        &self,
        auth_header: &str,
        action: &str,
        resource: &str,
    ) -> Result<String, AdminAuthError> {
        // 1. Parse Bearer token
        let token = Self::extract_bearer_token(auth_header)?;

        // 2. Decode JWT header, find kid
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AdminAuthError::InvalidToken(format!("malformed JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| AdminAuthError::InvalidToken("JWT header missing kid".to_string()))?;

        // 3. Build decoding key from JWKS
        let decoding_key = self.decoding_key_from_jwks(&kid)?;

        // 4. Build validation: check exp, iss, alg
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer_url]);
        // We don't enforce audience for admin tokens - they're internal
        validation.validate_aud = false;

        // 5. Decode and verify the token
        let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| {
                // Distinguish between expired tokens and other validation failures
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        AdminAuthError::TokenExpired
                    }
                    _ => AdminAuthError::InvalidToken(format!("JWT verification failed: {e}")),
                }
            })?;

        let claims = token_data.claims;

        // 6. Call local authorizer with billets as principals
        let authz_request = AdminAuthzRequest {
            principals: claims.billets.clone(),
            action: action.to_string(),
            resource: resource.to_string(),
            context: CommonContext {
                environment: String::new(),
                region: String::new(),
                request_time: chrono::Utc::now().to_rfc3339(),
                source_cloud: String::new(),
                selectors: vec![],
            },
        };

        let authorized = self
            .local_authorizer
            .is_authorized_admin(authz_request)
            .await
            .map_err(|e| {
                AdminAuthError::InvalidToken(format!("authorization evaluation failed: {e}"))
            })?;

        // 7. Return result
        if authorized {
            Ok(claims.sub)
        } else {
            Err(AdminAuthError::InsufficientPrivileges)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use crate::cedar::MockLocalAuthorizer;
    use crate::domain::token::{Claims, Es256Issuer, IssueRequest, Issuer};
    use crate::signing::static_key::StaticKeyManager;

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

    async fn issue_test_token(
        signing_manager: Arc<dyn SigningManager>,
        issuer_url: &str,
        spiffe_id: &str,
        billets: Vec<String>,
        ttl_secs: u64,
    ) -> String {
        let issuer = Es256Issuer::new(signing_manager, issuer_url.to_string(), ttl_secs);
        let req = IssueRequest {
            spiffe_id: spiffe_id.to_string(),
            audience: issuer_url.to_string(),
            billets,
        };
        issuer.issue(req).await.unwrap().access_token
    }

    #[tokio::test]
    async fn test_missing_credentials_empty_header() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator.authenticate("", "createBillet", "test").await;
        assert_eq!(result.unwrap_err(), AdminAuthError::MissingCredentials);
    }

    #[tokio::test]
    async fn test_missing_credentials_no_bearer_prefix() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate("Basic dXNlcjpwYXNz", "createBillet", "test")
            .await;
        assert_eq!(result.unwrap_err(), AdminAuthError::MissingCredentials);
    }

    #[tokio::test]
    async fn test_invalid_token_malformed_jwt() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate("Bearer not-a-valid-jwt", "createBillet", "test")
            .await;
        assert!(matches!(result.unwrap_err(), AdminAuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn test_expired_token() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        // Manually create a token with exp in the past
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = Claims {
            iss: "https://qm.example.com".to_string(),
            sub: "spiffe://example.com/workload".to_string(),
            aud: "https://qm.example.com".to_string(),
            billets: vec!["admin".to_string()],
            iat: now - 600,
            exp: now - 300, // expired 5 minutes ago
            jti: "test-jti".to_string(),
        };

        let header = signing_manager.header().clone();
        let token = jsonwebtoken::encode(&header, &claims, signing_manager.encoding_key())
            .expect("should encode");

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        assert_eq!(result.unwrap_err(), AdminAuthError::TokenExpired);
    }

    #[tokio::test]
    async fn test_invalid_token_wrong_issuer() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        // Issue token with wrong issuer
        let token = issue_test_token(
            signing_manager.clone(),
            "https://wrong-issuer.example.com",
            "spiffe://example.com/workload",
            vec!["admin".to_string()],
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        assert!(matches!(result.unwrap_err(), AdminAuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn test_insufficient_privileges() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();

        // Authorizer denies the request
        mock_authorizer
            .expect_is_authorized_admin()
            .returning(|_| Ok(false));

        let token = issue_test_token(
            signing_manager.clone(),
            "https://qm.example.com",
            "spiffe://example.com/workload",
            vec!["unprivileged-billet".to_string()],
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        assert_eq!(result.unwrap_err(), AdminAuthError::InsufficientPrivileges);
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();

        // Authorizer allows the request
        mock_authorizer
            .expect_is_authorized_admin()
            .returning(|_| Ok(true));

        let spiffe_id = "spiffe://example.com/admin-workload";
        let token = issue_test_token(
            signing_manager.clone(),
            "https://qm.example.com",
            spiffe_id,
            vec!["quartermaster-admin".to_string()],
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        assert_eq!(result.unwrap(), spiffe_id);
    }

    #[tokio::test]
    async fn test_authentication_passes_correct_action_and_resource() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();

        // Verify the action and resource are passed correctly
        mock_authorizer
            .expect_is_authorized_admin()
            .withf(|req: &AdminAuthzRequest| {
                req.action == "deleteBillet" && req.resource == "my-billet"
            })
            .returning(|_| Ok(true));

        let token = issue_test_token(
            signing_manager.clone(),
            "https://qm.example.com",
            "spiffe://example.com/admin",
            vec!["quartermaster-admin".to_string()],
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "deleteBillet", "my-billet")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authentication_passes_billets_as_principals() {
        let signing_manager = test_signing_manager();
        let mut mock_authorizer = MockLocalAuthorizer::new();

        let expected_billets = vec!["admin".to_string(), "superuser".to_string()];
        let expected_billets_clone = expected_billets.clone();

        mock_authorizer
            .expect_is_authorized_admin()
            .withf(move |req: &AdminAuthzRequest| req.principals == expected_billets_clone)
            .returning(|_| Ok(true));

        let token = issue_test_token(
            signing_manager.clone(),
            "https://qm.example.com",
            "spiffe://example.com/admin",
            expected_billets,
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_token_wrong_signing_key() {
        let signing_manager = test_signing_manager();
        let other_signing_manager = test_signing_manager(); // different key
        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_is_authorized_admin().never();

        // Issue token with a different key
        let token = issue_test_token(
            other_signing_manager,
            "https://qm.example.com",
            "spiffe://example.com/workload",
            vec!["admin".to_string()],
            300,
        )
        .await;

        let authenticator = AdminAuthenticatorImpl::new(
            signing_manager,
            Arc::new(mock_authorizer),
            "https://qm.example.com".to_string(),
        );

        let result = authenticator
            .authenticate(&format!("Bearer {token}"), "createBillet", "test")
            .await;
        // Should be InvalidToken since the kid won't match
        assert!(matches!(result.unwrap_err(), AdminAuthError::InvalidToken(_)));
    }
}
