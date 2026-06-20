//! Identity dispatcher — routes token validation to source-specific validators
//! based on the `subject_token_type` parameter.

use async_trait::async_trait;

use super::aws_sts::AwsStsValidator;
use super::gcp::GcpValidator;
use super::oidc::OidcValidator;
use super::{AuthenticatedIdentity, IdentityError, SpireIdentity};
use crate::domain::svid::{self, Validator as SvidValidator};

// ─── Token Type Constants ────────────────────────────────────────────────────

/// SPIRE JWT-SVID token type (RFC 8693 standard JWT type).
pub const TOKEN_TYPE_SPIRE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Corporate OIDC token type.
pub const TOKEN_TYPE_OIDC: &str = "urn:quartermaster:token-type:oidc";

/// AWS presigned GetCallerIdentity URL token type.
pub const TOKEN_TYPE_AWS_STS: &str = "urn:quartermaster:token-type:aws-presigned-sts";

/// GCP identity token type.
pub const TOKEN_TYPE_GCP: &str = "urn:quartermaster:token-type:gcp-identity";

// ─── IdentityDispatcher Trait ────────────────────────────────────────────────

/// Dispatches token validation to source-specific validators based on subject_token_type.
#[async_trait]
pub trait IdentityDispatcher: Send + Sync {
    async fn validate(
        &self,
        subject_token: &str,
        subject_token_type: &str,
    ) -> Result<AuthenticatedIdentity, IdentityError>;
}

// ─── DefaultIdentityDispatcher ───────────────────────────────────────────────

/// Default implementation that holds optional references to each source-specific validator.
pub struct DefaultIdentityDispatcher {
    spire_validator: Option<Box<dyn SvidValidator>>,
    oidc_validator: Option<Box<dyn OidcValidator>>,
    aws_sts_validator: Option<Box<dyn AwsStsValidator>>,
    gcp_validator: Option<Box<dyn GcpValidator>>,
}

impl DefaultIdentityDispatcher {
    /// Create a new dispatcher with the given validators.
    ///
    /// Any validator can be `None` if that identity source is not configured.
    /// Requests for unconfigured sources will return `IdentityError::UnknownTokenType`.
    pub fn new(
        spire_validator: Option<Box<dyn SvidValidator>>,
        oidc_validator: Option<Box<dyn OidcValidator>>,
        aws_sts_validator: Option<Box<dyn AwsStsValidator>>,
        gcp_validator: Option<Box<dyn GcpValidator>>,
    ) -> Self {
        Self {
            spire_validator,
            oidc_validator,
            aws_sts_validator,
            gcp_validator,
        }
    }
}

#[async_trait]
impl IdentityDispatcher for DefaultIdentityDispatcher {
    async fn validate(
        &self,
        subject_token: &str,
        subject_token_type: &str,
    ) -> Result<AuthenticatedIdentity, IdentityError> {
        match subject_token_type {
            TOKEN_TYPE_SPIRE => {
                let validator = self.spire_validator.as_ref().ok_or_else(|| {
                    IdentityError::UnknownTokenType(subject_token_type.to_string())
                })?;
                let claims = validator.validate(subject_token).await.map_err(|e| {
                    match e {
                        svid::SvidError::SignatureInvalid(msg) => {
                            IdentityError::InvalidSignature(msg)
                        }
                        svid::SvidError::Expired => IdentityError::TokenExpired,
                        svid::SvidError::UnknownTrustDomain(domain) => {
                            IdentityError::IssuerNotFound(domain)
                        }
                        svid::SvidError::InvalidAudience => {
                            IdentityError::AudienceMismatch("SVID audience mismatch".to_string())
                        }
                        svid::SvidError::MalformedToken(msg) => {
                            IdentityError::InvalidSignature(msg)
                        }
                    }
                })?;
                Ok(AuthenticatedIdentity::Spire(SpireIdentity {
                    spiffe_id: claims.spiffe_id,
                    trust_domain: claims.trust_domain,
                    environment: claims.environment,
                    region: claims.region,
                    audience: claims.audience,
                }))
            }
            TOKEN_TYPE_OIDC => {
                let validator = self.oidc_validator.as_ref().ok_or_else(|| {
                    IdentityError::UnknownTokenType(subject_token_type.to_string())
                })?;
                let identity = validator.validate(subject_token).await?;
                Ok(AuthenticatedIdentity::Oidc(identity))
            }
            TOKEN_TYPE_AWS_STS => {
                let validator = self.aws_sts_validator.as_ref().ok_or_else(|| {
                    IdentityError::UnknownTokenType(subject_token_type.to_string())
                })?;
                let identity = validator.validate(subject_token).await?;
                Ok(AuthenticatedIdentity::AwsSts(identity))
            }
            TOKEN_TYPE_GCP => {
                let validator = self.gcp_validator.as_ref().ok_or_else(|| {
                    IdentityError::UnknownTokenType(subject_token_type.to_string())
                })?;
                let identity = validator.validate(subject_token).await?;
                Ok(AuthenticatedIdentity::Gcp(identity))
            }
            _ => Err(IdentityError::UnknownTokenType(
                subject_token_type.to_string(),
            )),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::identity::{AwsStsIdentity, GcpIdentity, OidcIdentity};
    use std::collections::HashMap;

    // ─── Mock Validators ─────────────────────────────────────────────────────

    struct MockSvidValidator {
        result: Result<svid::Claims, svid::SvidError>,
    }

    #[async_trait]
    impl SvidValidator for MockSvidValidator {
        async fn validate(&self, _raw_token: &str) -> Result<svid::Claims, svid::SvidError> {
            self.result.clone()
        }
    }

    struct MockOidcValidator {
        result: Result<OidcIdentity, IdentityError>,
    }

    #[async_trait]
    impl OidcValidator for MockOidcValidator {
        async fn validate(&self, _token: &str) -> Result<OidcIdentity, IdentityError> {
            self.result.clone()
        }
    }

    struct MockAwsStsValidator {
        result: Result<AwsStsIdentity, IdentityError>,
    }

    #[async_trait]
    impl AwsStsValidator for MockAwsStsValidator {
        async fn validate(&self, _presigned_url: &str) -> Result<AwsStsIdentity, IdentityError> {
            self.result.clone()
        }
    }

    struct MockGcpValidator {
        result: Result<GcpIdentity, IdentityError>,
    }

    #[async_trait]
    impl GcpValidator for MockGcpValidator {
        async fn validate(&self, _token: &str) -> Result<GcpIdentity, IdentityError> {
            self.result.clone()
        }
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    fn sample_svid_claims() -> svid::Claims {
        svid::Claims {
            spiffe_id: "spiffe://example.com/ns/prod/workload/api".to_string(),
            trust_domain: "example.com".to_string(),
            environment: "ns".to_string(),
            region: "prod".to_string(),
            audience: vec!["https://qm.example.com".to_string()],
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        }
    }

    fn sample_oidc_identity() -> OidcIdentity {
        OidcIdentity {
            email: "alice@corp.example.com".to_string(),
            idp_prefix: "okta".to_string(),
            claims: HashMap::from([(
                "groups".to_string(),
                vec!["engineering".to_string(), "billing-ops".to_string()],
            )]),
            subject: "auth0|12345".to_string(),
        }
    }

    fn sample_aws_sts_identity() -> AwsStsIdentity {
        AwsStsIdentity {
            account_id: "123456789012".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/billing-service".to_string(),
            role_name: "billing-service".to_string(),
            role_path: "/".to_string(),
            session_name: "session-abc".to_string(),
        }
    }

    fn sample_gcp_identity() -> GcpIdentity {
        GcpIdentity {
            project_id: "my-project".to_string(),
            email: "sa@my-project.iam.gserviceaccount.com".to_string(),
            zone: "us-central1-a".to_string(),
            unique_id: "112233445566".to_string(),
        }
    }

    // ─── Dispatch Routing Tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_dispatch_spire_token_type() {
        let dispatcher = DefaultIdentityDispatcher::new(
            Some(Box::new(MockSvidValidator {
                result: Ok(sample_svid_claims()),
            })),
            None,
            None,
            None,
        );

        let result = dispatcher.validate("some-jwt", TOKEN_TYPE_SPIRE).await;
        assert!(result.is_ok());
        match result.unwrap() {
            AuthenticatedIdentity::Spire(spire) => {
                assert_eq!(spire.spiffe_id, "spiffe://example.com/ns/prod/workload/api");
                assert_eq!(spire.trust_domain, "example.com");
                assert_eq!(spire.environment, "ns");
                assert_eq!(spire.region, "prod");
            }
            other => panic!("expected Spire variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dispatch_oidc_token_type() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            Some(Box::new(MockOidcValidator {
                result: Ok(sample_oidc_identity()),
            })),
            None,
            None,
        );

        let result = dispatcher.validate("oidc-token", TOKEN_TYPE_OIDC).await;
        assert!(result.is_ok());
        match result.unwrap() {
            AuthenticatedIdentity::Oidc(oidc) => {
                assert_eq!(oidc.email, "alice@corp.example.com");
                assert_eq!(oidc.idp_prefix, "okta");
            }
            other => panic!("expected Oidc variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dispatch_aws_sts_token_type() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            None,
            Some(Box::new(MockAwsStsValidator {
                result: Ok(sample_aws_sts_identity()),
            })),
            None,
        );

        let result = dispatcher.validate("presigned-url", TOKEN_TYPE_AWS_STS).await;
        assert!(result.is_ok());
        match result.unwrap() {
            AuthenticatedIdentity::AwsSts(aws) => {
                assert_eq!(aws.account_id, "123456789012");
                assert_eq!(aws.role_name, "billing-service");
            }
            other => panic!("expected AwsSts variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dispatch_gcp_token_type() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            None,
            None,
            Some(Box::new(MockGcpValidator {
                result: Ok(sample_gcp_identity()),
            })),
        );

        let result = dispatcher.validate("gcp-token", TOKEN_TYPE_GCP).await;
        assert!(result.is_ok());
        match result.unwrap() {
            AuthenticatedIdentity::Gcp(gcp) => {
                assert_eq!(gcp.project_id, "my-project");
                assert_eq!(gcp.email, "sa@my-project.iam.gserviceaccount.com");
            }
            other => panic!("expected Gcp variant, got {:?}", other),
        }
    }

    // ─── Unknown Token Type Tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_unknown_token_type_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(
            Some(Box::new(MockSvidValidator {
                result: Ok(sample_svid_claims()),
            })),
            Some(Box::new(MockOidcValidator {
                result: Ok(sample_oidc_identity()),
            })),
            Some(Box::new(MockAwsStsValidator {
                result: Ok(sample_aws_sts_identity()),
            })),
            Some(Box::new(MockGcpValidator {
                result: Ok(sample_gcp_identity()),
            })),
        );

        let result = dispatcher
            .validate("token", "urn:unknown:token-type:foo")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::UnknownTokenType(t) => {
                assert_eq!(t, "urn:unknown:token-type:foo");
            }
            other => panic!("expected UnknownTokenType, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_empty_token_type_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(None, None, None, None);

        let result = dispatcher.validate("token", "").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::UnknownTokenType(_)
        ));
    }

    // ─── Unconfigured Source Tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_spire_not_configured_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(None, None, None, None);

        let result = dispatcher.validate("jwt", TOKEN_TYPE_SPIRE).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::UnknownTokenType(t) => {
                assert_eq!(t, TOKEN_TYPE_SPIRE);
            }
            other => panic!("expected UnknownTokenType, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_oidc_not_configured_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(None, None, None, None);

        let result = dispatcher.validate("token", TOKEN_TYPE_OIDC).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::UnknownTokenType(_)
        ));
    }

    #[tokio::test]
    async fn test_aws_sts_not_configured_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(None, None, None, None);

        let result = dispatcher.validate("url", TOKEN_TYPE_AWS_STS).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::UnknownTokenType(_)
        ));
    }

    #[tokio::test]
    async fn test_gcp_not_configured_returns_error() {
        let dispatcher = DefaultIdentityDispatcher::new(None, None, None, None);

        let result = dispatcher.validate("token", TOKEN_TYPE_GCP).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::UnknownTokenType(_)
        ));
    }

    // ─── Error Propagation Tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_spire_error_maps_to_identity_error() {
        let dispatcher = DefaultIdentityDispatcher::new(
            Some(Box::new(MockSvidValidator {
                result: Err(svid::SvidError::Expired),
            })),
            None,
            None,
            None,
        );

        let result = dispatcher.validate("expired-jwt", TOKEN_TYPE_SPIRE).await;
        assert_eq!(result.unwrap_err(), IdentityError::TokenExpired);
    }

    #[tokio::test]
    async fn test_spire_signature_error_maps_correctly() {
        let dispatcher = DefaultIdentityDispatcher::new(
            Some(Box::new(MockSvidValidator {
                result: Err(svid::SvidError::SignatureInvalid("bad sig".to_string())),
            })),
            None,
            None,
            None,
        );

        let result = dispatcher.validate("bad-jwt", TOKEN_TYPE_SPIRE).await;
        match result.unwrap_err() {
            IdentityError::InvalidSignature(msg) => assert_eq!(msg, "bad sig"),
            other => panic!("expected InvalidSignature, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_spire_unknown_trust_domain_maps_correctly() {
        let dispatcher = DefaultIdentityDispatcher::new(
            Some(Box::new(MockSvidValidator {
                result: Err(svid::SvidError::UnknownTrustDomain("evil.com".to_string())),
            })),
            None,
            None,
            None,
        );

        let result = dispatcher.validate("jwt", TOKEN_TYPE_SPIRE).await;
        match result.unwrap_err() {
            IdentityError::IssuerNotFound(domain) => assert_eq!(domain, "evil.com"),
            other => panic!("expected IssuerNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_oidc_validator_error_propagates() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            Some(Box::new(MockOidcValidator {
                result: Err(IdentityError::TokenExpired),
            })),
            None,
            None,
        );

        let result = dispatcher.validate("expired-oidc", TOKEN_TYPE_OIDC).await;
        assert_eq!(result.unwrap_err(), IdentityError::TokenExpired);
    }

    #[tokio::test]
    async fn test_aws_sts_validator_error_propagates() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            None,
            Some(Box::new(MockAwsStsValidator {
                result: Err(IdentityError::InvalidPresignedUrl(
                    "bad host".to_string(),
                )),
            })),
            None,
        );

        let result = dispatcher.validate("bad-url", TOKEN_TYPE_AWS_STS).await;
        match result.unwrap_err() {
            IdentityError::InvalidPresignedUrl(msg) => assert_eq!(msg, "bad host"),
            other => panic!("expected InvalidPresignedUrl, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_gcp_validator_error_propagates() {
        let dispatcher = DefaultIdentityDispatcher::new(
            None,
            None,
            None,
            Some(Box::new(MockGcpValidator {
                result: Err(IdentityError::AudienceMismatch("wrong aud".to_string())),
            })),
        );

        let result = dispatcher.validate("gcp-token", TOKEN_TYPE_GCP).await;
        match result.unwrap_err() {
            IdentityError::AudienceMismatch(msg) => assert_eq!(msg, "wrong aud"),
            other => panic!("expected AudienceMismatch, got {:?}", other),
        }
    }

    // ─── Token Type Constants Tests ──────────────────────────────────────────

    #[test]
    fn test_token_type_constants() {
        assert_eq!(TOKEN_TYPE_SPIRE, "urn:ietf:params:oauth:token-type:jwt");
        assert_eq!(TOKEN_TYPE_OIDC, "urn:quartermaster:token-type:oidc");
        assert_eq!(
            TOKEN_TYPE_AWS_STS,
            "urn:quartermaster:token-type:aws-presigned-sts"
        );
        assert_eq!(TOKEN_TYPE_GCP, "urn:quartermaster:token-type:gcp-identity");
    }
}
