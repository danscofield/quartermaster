pub mod aws_sts;
pub mod claims;
pub mod dispatcher;
pub mod entity;
pub mod gcp;
pub mod implicit;
pub mod jwks;
pub mod mtls;
pub mod oidc;
pub mod path_pattern;
pub mod selector_enricher;
pub mod subject;

use std::collections::HashMap;
use std::fmt;

/// The result of successfully validating an upstream identity token.
/// Each variant carries source-specific claims needed for Cedar entity construction.
#[derive(Debug, Clone)]
pub enum AuthenticatedIdentity {
    Spire(SpireIdentity),
    Oidc(OidcIdentity),
    AwsSts(AwsStsIdentity),
    Gcp(GcpIdentity),
}

#[derive(Debug, Clone)]
pub struct SpireIdentity {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub environment: String,
    pub region: String,
    pub audience: Vec<String>,
}

/// Indicates whether a `SpireIdentity` was authenticated via JWT-SVID (token exchange)
/// or mTLS client certificate (X.509-SVID). Used to differentiate the audit `source_type`:
/// `"spire"` for JWT-SVIDs and `"mtls-spiffe"` for mTLS-derived identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpireAuthSource {
    /// Identity was authenticated via a SPIRE JWT-SVID token.
    JwtSvid,
    /// Identity was authenticated via an mTLS client certificate (X.509-SVID).
    MtlsCert,
}

#[derive(Debug, Clone)]
pub struct OidcIdentity {
    pub email: String,
    pub idp_prefix: String,
    /// All extracted claims keyed by claim name (e.g., "groups", "roles", custom claims).
    /// The entity builder pulls from this map; the Cedar entity flattens all values into `groups`.
    pub claims: HashMap<String, Vec<String>>,
    pub subject: String,
}

#[derive(Debug, Clone)]
pub struct AwsStsIdentity {
    pub account_id: String,
    pub role_arn: String,
    pub role_name: String,
    pub role_path: String,
    pub session_name: String,
}

#[derive(Debug, Clone)]
pub struct GcpIdentity {
    pub project_id: String,
    pub email: String,
    pub zone: String,
    pub unique_id: String,
}

/// Errors that can occur during identity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The subject_token_type is not recognized.
    UnknownTokenType(String),
    /// The token issuer does not match any configured identity source.
    IssuerNotFound(String),
    /// Token signature verification failed.
    InvalidSignature(String),
    /// The token has expired.
    TokenExpired,
    /// The token audience does not match any allowed audience.
    AudienceMismatch(String),
    /// JWKS for the identity source is stale beyond the allowed threshold.
    KeysStale(String),
    /// The presigned URL is invalid or has expired.
    InvalidPresignedUrl(String),
    /// The upstream identity call (e.g., STS GetCallerIdentity) failed.
    UpstreamCallFailed(String),
    /// The identity's account/project is not in the configured allowlist.
    NotAllowed(String),
    /// A required claim is missing from the token.
    MissingClaim(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::UnknownTokenType(t) => {
                write!(f, "unknown subject_token_type: {}", t)
            }
            IdentityError::IssuerNotFound(iss) => {
                write!(f, "token issuer does not match any configured source: {}", iss)
            }
            IdentityError::InvalidSignature(detail) => {
                write!(f, "token signature verification failed: {}", detail)
            }
            IdentityError::TokenExpired => {
                write!(f, "token has expired")
            }
            IdentityError::AudienceMismatch(aud) => {
                write!(f, "token audience not in allowed list: {}", aud)
            }
            IdentityError::KeysStale(source) => {
                write!(f, "JWKS stale for source: {}", source)
            }
            IdentityError::InvalidPresignedUrl(detail) => {
                write!(f, "invalid presigned URL: {}", detail)
            }
            IdentityError::UpstreamCallFailed(detail) => {
                write!(f, "upstream identity call failed: {}", detail)
            }
            IdentityError::NotAllowed(detail) => {
                write!(f, "identity not in allowlist: {}", detail)
            }
            IdentityError::MissingClaim(claim) => {
                write!(f, "missing required claim: {}", claim)
            }
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_error_display() {
        let err = IdentityError::UnknownTokenType("foo:bar".into());
        assert_eq!(format!("{err}"), "unknown subject_token_type: foo:bar");

        let err = IdentityError::IssuerNotFound("https://evil.example.com".into());
        assert!(format!("{err}").contains("does not match"));

        let err = IdentityError::TokenExpired;
        assert_eq!(format!("{err}"), "token has expired");

        let err = IdentityError::KeysStale("okta".into());
        assert!(format!("{err}").contains("stale"));
    }

    #[test]
    fn test_identity_error_is_error_trait() {
        let err: Box<dyn std::error::Error> =
            Box::new(IdentityError::TokenExpired);
        assert_eq!(format!("{err}"), "token has expired");
    }

    #[test]
    fn test_authenticated_identity_enum_variants() {
        let spire = AuthenticatedIdentity::Spire(SpireIdentity {
            spiffe_id: "spiffe://example.com/ns/default/workload/api".into(),
            trust_domain: "example.com".into(),
            environment: "production".into(),
            region: "us-east-1".into(),
            audience: vec!["quartermaster".into()],
        });
        assert!(matches!(spire, AuthenticatedIdentity::Spire(_)));

        let oidc = AuthenticatedIdentity::Oidc(OidcIdentity {
            email: "alice@corp.example.com".into(),
            idp_prefix: "okta".into(),
            claims: HashMap::from([
                ("groups".into(), vec!["engineering".into(), "billing-ops".into()]),
            ]),
            subject: "auth0|12345".into(),
        });
        assert!(matches!(oidc, AuthenticatedIdentity::Oidc(_)));

        let aws = AuthenticatedIdentity::AwsSts(AwsStsIdentity {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/billing-service".into(),
            role_name: "billing-service".into(),
            role_path: "/".into(),
            session_name: "session-abc".into(),
        });
        assert!(matches!(aws, AuthenticatedIdentity::AwsSts(_)));

        let gcp = AuthenticatedIdentity::Gcp(GcpIdentity {
            project_id: "my-project".into(),
            email: "sa@my-project.iam.gserviceaccount.com".into(),
            zone: "us-central1-a".into(),
            unique_id: "112233445566".into(),
        });
        assert!(matches!(gcp, AuthenticatedIdentity::Gcp(_)));
    }

    #[test]
    fn test_oidc_identity_claims_map() {
        let identity = OidcIdentity {
            email: "bob@example.com".into(),
            idp_prefix: "azure".into(),
            claims: HashMap::from([
                ("groups".into(), vec!["admins".into()]),
                ("roles".into(), vec!["reader".into(), "writer".into()]),
            ]),
            subject: "sub-xyz".into(),
        };
        assert_eq!(identity.claims.len(), 2);
        assert_eq!(identity.claims["groups"], vec!["admins"]);
        assert_eq!(identity.claims["roles"], vec!["reader", "writer"]);
    }

    #[test]
    fn test_structs_are_clone() {
        let spire = SpireIdentity {
            spiffe_id: "spiffe://test/workload".into(),
            trust_domain: "test".into(),
            environment: "dev".into(),
            region: "local".into(),
            audience: vec!["aud".into()],
        };
        let _cloned = spire.clone();

        let aws = AwsStsIdentity {
            account_id: "111".into(),
            role_arn: "arn:aws:iam::111:role/r".into(),
            role_name: "r".into(),
            role_path: "/".into(),
            session_name: "s".into(),
        };
        let _cloned = aws.clone();
    }
}
