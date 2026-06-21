// Multi-source Cedar entity builder — constructs principal entities for any identity source.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Context, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression,
};

use crate::domain::identity::{
    AuthenticatedIdentity, AwsStsIdentity, GcpIdentity, OidcIdentity, SpireAuthSource,
};

#[cfg(test)]
use crate::domain::identity::SpireIdentity;

/// Namespace for all Quartermaster Cedar entity types.
const NAMESPACE: &str = "Quartermaster";

/// Error type for entity construction failures.
#[derive(Debug)]
pub enum EntityBuildError {
    InvalidEntityType(String),
    EntityCreationFailed(String),
    ContextCreationFailed(String),
}

impl std::fmt::Display for EntityBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityBuildError::InvalidEntityType(msg) => {
                write!(f, "invalid entity type: {msg}")
            }
            EntityBuildError::EntityCreationFailed(msg) => {
                write!(f, "entity creation failed: {msg}")
            }
            EntityBuildError::ContextCreationFailed(msg) => {
                write!(f, "context creation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for EntityBuildError {}

/// A Cedar principal entity for any identity source.
#[derive(Debug, Clone)]
pub enum CedarPrincipal {
    /// OIDC identity (human or service) from an OIDC IdP
    Oidc(OidcEntity),
    /// AWS IAM role identity from presigned STS
    AwsRole(AwsRoleEntity),
    /// GCP workload/service account identity
    GcpWorkload(GcpWorkloadEntity),
}

/// Cedar entity representation of an OIDC identity (human or service).
#[derive(Debug, Clone)]
pub struct OidcEntity {
    pub email: String,
    pub idp_prefix: String,
    pub subject: String,
    pub subject_type: String,
    pub groups: Vec<String>,
    pub claims: Vec<String>,
}

/// Cedar entity representation of an AWS IAM role identity.
#[derive(Debug, Clone)]
pub struct AwsRoleEntity {
    pub account_id: String,
    pub role_arn: String,
    pub role_name: String,
    pub role_path: String,
}

/// Cedar entity representation of a GCP workload identity.
#[derive(Debug, Clone)]
pub struct GcpWorkloadEntity {
    pub project_id: String,
    pub email: String,
    pub zone: String,
}

/// Builds Cedar principal entities from any AuthenticatedIdentity variant.
pub struct MultiSourceEntityBuilder;

impl MultiSourceEntityBuilder {
    /// Creates a new MultiSourceEntityBuilder.
    pub fn new() -> Self {
        Self
    }

    /// Builds a CedarPrincipal from an AuthenticatedIdentity.
    ///
    /// Only handles non-SPIRE sources. SPIRE identities use path-pattern extraction
    /// and `build_workload_entities_from_captures` directly in the resolver.
    pub fn build_principal(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> CedarPrincipal {
        match identity {
            AuthenticatedIdentity::Spire(_) => {
                // SPIRE identities are no longer routed through MultiSourceEntityBuilder.
                // They use path-pattern extraction in the resolver directly.
                panic!("SPIRE identities should not be routed through MultiSourceEntityBuilder")
            }
            AuthenticatedIdentity::Oidc(oidc) => {
                CedarPrincipal::Oidc(Self::build_oidc_entity(oidc))
            }
            AuthenticatedIdentity::AwsSts(aws) => {
                CedarPrincipal::AwsRole(Self::build_aws_role_entity(aws))
            }
            AuthenticatedIdentity::Gcp(gcp) => {
                CedarPrincipal::GcpWorkload(Self::build_gcp_entity(gcp))
            }
        }
    }

    /// Builds an OidcEntity from an OidcIdentity.
    /// Flattens all values from the claims map into a single `groups` set,
    /// and builds origin-preserving `claims` as "claim_name:value" strings.
    fn build_oidc_entity(oidc: &OidcIdentity) -> OidcEntity {
        let mut groups: Vec<String> = oidc
            .claims
            .values()
            .flatten()
            .cloned()
            .collect();
        groups.sort();
        groups.dedup();

        let mut claims: Vec<String> = oidc
            .claims
            .iter()
            .flat_map(|(claim_name, values)| {
                values.iter().map(move |v| format!("{claim_name}:{v}"))
            })
            .collect();
        claims.sort();
        claims.dedup();

        OidcEntity {
            email: oidc.email.clone(),
            idp_prefix: oidc.idp_prefix.clone(),
            subject: oidc.subject.clone(),
            subject_type: "human".to_string(),
            groups,
            claims,
        }
    }

    /// Builds an AwsRoleEntity from an AwsStsIdentity.
    fn build_aws_role_entity(aws: &AwsStsIdentity) -> AwsRoleEntity {
        AwsRoleEntity {
            account_id: aws.account_id.clone(),
            role_arn: aws.role_arn.clone(),
            role_name: aws.role_name.clone(),
            role_path: aws.role_path.clone(),
        }
    }

    /// Builds a GcpWorkloadEntity from a GcpIdentity.
    fn build_gcp_entity(gcp: &GcpIdentity) -> GcpWorkloadEntity {
        GcpWorkloadEntity {
            project_id: gcp.project_id.clone(),
            email: gcp.email.clone(),
            zone: gcp.zone.clone(),
        }
    }
}

/// Constructs a Cedar Entity from a CedarPrincipal for use in policy evaluation.
pub fn build_cedar_entity(principal: &CedarPrincipal) -> Result<Entity, EntityBuildError> {
    match principal {
        CedarPrincipal::Oidc(oidc) => build_oidc_cedar_entity(oidc),
        CedarPrincipal::AwsRole(aws) => build_aws_cedar_entity(aws),
        CedarPrincipal::GcpWorkload(gcp) => build_gcp_cedar_entity(gcp),
    }
}

/// Constructs the Cedar EntityUid for a CedarPrincipal.
pub fn principal_entity_uid(principal: &CedarPrincipal) -> Result<EntityUid, EntityBuildError> {
    match principal {
        CedarPrincipal::Oidc(oidc) => make_entity_uid("OidcIdentity", &oidc.email),
        CedarPrincipal::AwsRole(aws) => make_entity_uid("AwsRoleIdentity", &aws.role_arn),
        CedarPrincipal::GcpWorkload(gcp) => {
            make_entity_uid("GcpIdentity", &gcp.email)
        }
    }
}

/// Returns the `source_type` string for a given identity.
///
/// For `Spire` identities, this defaults to `"spire"` (JWT-SVID).
/// Use [`source_type_for_spire_identity`] when the `SpireAuthSource` is known
/// to distinguish between JWT-SVID (`"spire"`) and mTLS (`"mtls-spiffe"`).
pub fn source_type_for_identity(identity: &AuthenticatedIdentity) -> &'static str {
    match identity {
        AuthenticatedIdentity::Spire(_) => "spire",
        AuthenticatedIdentity::Oidc(_) => "oidc",
        AuthenticatedIdentity::AwsSts(_) => "aws-sts",
        AuthenticatedIdentity::Gcp(_) => "gcp",
    }
}

/// Returns the `source_type` string for a SPIRE identity based on the authentication source.
///
/// - `SpireAuthSource::JwtSvid` → `"spire"` (standard JWT-SVID token exchange)
/// - `SpireAuthSource::MtlsCert` → `"mtls-spiffe"` (mTLS client certificate)
pub fn source_type_for_spire_identity(source: SpireAuthSource) -> &'static str {
    match source {
        SpireAuthSource::JwtSvid => "spire",
        SpireAuthSource::MtlsCert => "mtls-spiffe",
    }
}

/// Builds a Cedar Context that includes the `source_type` field.
pub fn build_identity_context(
    identity: &AuthenticatedIdentity,
    environment: &str,
    region: &str,
    request_time: &str,
    selectors: &[String],
) -> Result<Context, EntityBuildError> {
    let source_type = source_type_for_identity(identity);

    let pairs = vec![
        (
            "environment".to_string(),
            RestrictedExpression::new_string(environment.to_string()),
        ),
        (
            "region".to_string(),
            RestrictedExpression::new_string(region.to_string()),
        ),
        (
            "request_time".to_string(),
            RestrictedExpression::new_string(request_time.to_string()),
        ),
        (
            "source_type".to_string(),
            RestrictedExpression::new_string(source_type.to_string()),
        ),
        (
            "source_cloud".to_string(),
            RestrictedExpression::new_string(source_cloud_for_identity(identity).to_string()),
        ),
        (
            "selectors".to_string(),
            string_set_expr(selectors),
        ),
    ];

    Context::from_pairs(pairs)
        .map_err(|e| EntityBuildError::ContextCreationFailed(format!("{e}")))
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Returns the source_cloud value based on identity type.
fn source_cloud_for_identity(identity: &AuthenticatedIdentity) -> &'static str {
    match identity {
        AuthenticatedIdentity::Spire(_) => "",
        AuthenticatedIdentity::Oidc(_) => "",
        AuthenticatedIdentity::AwsSts(_) => "aws",
        AuthenticatedIdentity::Gcp(_) => "gcp",
    }
}

/// Constructs a Cedar EntityUid within the Quartermaster namespace.
fn make_entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, EntityBuildError> {
    let type_name = EntityTypeName::from_str(&format!("{NAMESPACE}::{entity_type}"))
        .map_err(|e| EntityBuildError::InvalidEntityType(format!("{e}")))?;
    let entity_id = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Creates a RestrictedExpression for a Set of strings.
fn string_set_expr(values: &[String]) -> RestrictedExpression {
    RestrictedExpression::new_set(
        values
            .iter()
            .map(|s| RestrictedExpression::new_string(s.clone())),
    )
}

/// Builds a Cedar Entity for an OidcIdentity principal.
fn build_oidc_cedar_entity(oidc: &OidcEntity) -> Result<Entity, EntityBuildError> {
    let uid = make_entity_uid("OidcIdentity", &oidc.email)?;

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert(
        "email".to_string(),
        RestrictedExpression::new_string(oidc.email.clone()),
    );
    attrs.insert(
        "idp_prefix".to_string(),
        RestrictedExpression::new_string(oidc.idp_prefix.clone()),
    );
    attrs.insert(
        "groups".to_string(),
        string_set_expr(&oidc.groups),
    );
    attrs.insert(
        "subject".to_string(),
        RestrictedExpression::new_string(oidc.subject.clone()),
    );
    attrs.insert(
        "subject_type".to_string(),
        RestrictedExpression::new_string(oidc.subject_type.clone()),
    );
    attrs.insert(
        "claims".to_string(),
        string_set_expr(&oidc.claims),
    );

    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| EntityBuildError::EntityCreationFailed(format!("{e}")))
}

/// Builds a Cedar Entity for an AwsRoleIdentity principal.
fn build_aws_cedar_entity(aws: &AwsRoleEntity) -> Result<Entity, EntityBuildError> {
    let uid = make_entity_uid("AwsRoleIdentity", &aws.role_arn)?;

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert(
        "account_id".to_string(),
        RestrictedExpression::new_string(aws.account_id.clone()),
    );
    attrs.insert(
        "role_arn".to_string(),
        RestrictedExpression::new_string(aws.role_arn.clone()),
    );
    attrs.insert(
        "role_name".to_string(),
        RestrictedExpression::new_string(aws.role_name.clone()),
    );
    attrs.insert(
        "role_path".to_string(),
        RestrictedExpression::new_string(aws.role_path.clone()),
    );

    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| EntityBuildError::EntityCreationFailed(format!("{e}")))
}

/// Builds a Cedar Entity for a GcpIdentity principal.
fn build_gcp_cedar_entity(gcp: &GcpWorkloadEntity) -> Result<Entity, EntityBuildError> {
    let uid = make_entity_uid("GcpIdentity", &gcp.email)?;

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert(
        "project_id".to_string(),
        RestrictedExpression::new_string(gcp.project_id.clone()),
    );
    attrs.insert(
        "email".to_string(),
        RestrictedExpression::new_string(gcp.email.clone()),
    );
    attrs.insert(
        "zone".to_string(),
        RestrictedExpression::new_string(gcp.zone.clone()),
    );

    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| EntityBuildError::EntityCreationFailed(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_oidc_identity() -> OidcIdentity {
        OidcIdentity {
            email: "alice@corp.example.com".to_string(),
            idp_prefix: "okta".to_string(),
            claims: HashMap::from([
                (
                    "groups".to_string(),
                    vec!["engineering".to_string(), "billing-ops".to_string()],
                ),
                (
                    "roles".to_string(),
                    vec!["admin".to_string(), "reader".to_string()],
                ),
            ]),
            subject: "auth0|12345".to_string(),
        }
    }

    fn make_aws_identity() -> AwsStsIdentity {
        AwsStsIdentity {
            account_id: "123456789012".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/billing-service".to_string(),
            role_name: "billing-service".to_string(),
            role_path: "/services/".to_string(),
            session_name: "session-abc".to_string(),
        }
    }

    fn make_gcp_identity() -> GcpIdentity {
        GcpIdentity {
            project_id: "my-project-123".to_string(),
            email: "sa@my-project-123.iam.gserviceaccount.com".to_string(),
            zone: "us-central1-a".to_string(),
            unique_id: "112233445566".to_string(),
        }
    }

    fn make_spire_identity() -> SpireIdentity {
        SpireIdentity {
            spiffe_id: "spiffe://example.com/ns/finance/workload/payments".to_string(),
            trust_domain: "example.com".to_string(),
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            audience: vec!["quartermaster".to_string()],
        }
    }

    #[test]
    fn test_build_human_entity_from_oidc() {
        let builder = MultiSourceEntityBuilder::new();
        let oidc = make_oidc_identity();
        let identity = AuthenticatedIdentity::Oidc(oidc.clone());

        let principal = builder.build_principal(&identity);

        match principal {
            CedarPrincipal::Oidc(entity) => {
                assert_eq!(entity.email, "alice@corp.example.com");
                assert_eq!(entity.idp_prefix, "okta");
                // groups should be flattened from all claims, sorted and deduped
                assert!(entity.groups.contains(&"engineering".to_string()));
                assert!(entity.groups.contains(&"billing-ops".to_string()));
                assert!(entity.groups.contains(&"admin".to_string()));
                assert!(entity.groups.contains(&"reader".to_string()));
                assert_eq!(entity.groups.len(), 4);
            }
            _ => panic!("Expected CedarPrincipal::Oidc"),
        }
    }

    #[test]
    fn test_build_human_entity_deduplicates_groups() {
        let builder = MultiSourceEntityBuilder::new();
        let oidc = OidcIdentity {
            email: "bob@example.com".to_string(),
            idp_prefix: "azure".to_string(),
            claims: HashMap::from([
                ("groups".to_string(), vec!["admins".to_string(), "ops".to_string()]),
                ("roles".to_string(), vec!["admins".to_string(), "reader".to_string()]),
            ]),
            subject: "sub-xyz".to_string(),
        };
        let identity = AuthenticatedIdentity::Oidc(oidc);

        let principal = builder.build_principal(&identity);

        match principal {
            CedarPrincipal::Oidc(entity) => {
                // "admins" appears in both claims but should be deduped
                assert_eq!(entity.groups.len(), 3);
                assert!(entity.groups.contains(&"admins".to_string()));
                assert!(entity.groups.contains(&"ops".to_string()));
                assert!(entity.groups.contains(&"reader".to_string()));
            }
            _ => panic!("Expected CedarPrincipal::Oidc"),
        }
    }

    #[test]
    fn test_build_human_entity_empty_claims() {
        let builder = MultiSourceEntityBuilder::new();
        let oidc = OidcIdentity {
            email: "user@example.com".to_string(),
            idp_prefix: "custom".to_string(),
            claims: HashMap::new(),
            subject: "sub-1".to_string(),
        };
        let identity = AuthenticatedIdentity::Oidc(oidc);

        let principal = builder.build_principal(&identity);

        match principal {
            CedarPrincipal::Oidc(entity) => {
                assert_eq!(entity.email, "user@example.com");
                assert_eq!(entity.idp_prefix, "custom");
                assert!(entity.groups.is_empty());
            }
            _ => panic!("Expected CedarPrincipal::Oidc"),
        }
    }

    #[test]
    fn test_build_aws_role_entity() {
        let builder = MultiSourceEntityBuilder::new();
        let aws = make_aws_identity();
        let identity = AuthenticatedIdentity::AwsSts(aws.clone());

        let principal = builder.build_principal(&identity);

        match principal {
            CedarPrincipal::AwsRole(role) => {
                assert_eq!(role.account_id, "123456789012");
                assert_eq!(
                    role.role_arn,
                    "arn:aws:iam::123456789012:role/billing-service"
                );
                assert_eq!(role.role_name, "billing-service");
                assert_eq!(role.role_path, "/services/");
            }
            _ => panic!("Expected CedarPrincipal::AwsRole"),
        }
    }

    #[test]
    fn test_build_gcp_entity() {
        let builder = MultiSourceEntityBuilder::new();
        let gcp = make_gcp_identity();
        let identity = AuthenticatedIdentity::Gcp(gcp.clone());

        let principal = builder.build_principal(&identity);

        match principal {
            CedarPrincipal::GcpWorkload(gcp_entity) => {
                assert_eq!(gcp_entity.project_id, "my-project-123");
                assert_eq!(
                    gcp_entity.email,
                    "sa@my-project-123.iam.gserviceaccount.com"
                );
                assert_eq!(gcp_entity.zone, "us-central1-a");
            }
            _ => panic!("Expected CedarPrincipal::GcpWorkload"),
        }
    }

    #[test]
    fn test_source_type_for_each_variant() {
        assert_eq!(
            source_type_for_identity(&AuthenticatedIdentity::Spire(make_spire_identity())),
            "spire"
        );
        assert_eq!(
            source_type_for_identity(&AuthenticatedIdentity::Oidc(make_oidc_identity())),
            "oidc"
        );
        assert_eq!(
            source_type_for_identity(&AuthenticatedIdentity::AwsSts(make_aws_identity())),
            "aws-sts"
        );
        assert_eq!(
            source_type_for_identity(&AuthenticatedIdentity::Gcp(make_gcp_identity())),
            "gcp"
        );
    }

    #[test]
    fn test_source_type_for_spire_identity_jwt() {
        assert_eq!(
            source_type_for_spire_identity(SpireAuthSource::JwtSvid),
            "spire"
        );
    }

    #[test]
    fn test_source_type_for_spire_identity_mtls() {
        assert_eq!(
            source_type_for_spire_identity(SpireAuthSource::MtlsCert),
            "mtls-spiffe"
        );
    }

    #[test]
    fn test_build_cedar_entity_oidc() {
        let oidc = OidcEntity {
            email: "alice@example.com".to_string(),
            idp_prefix: "okta".to_string(),
            subject: "sub-123".to_string(),
            subject_type: "human".to_string(),
            groups: vec!["eng".to_string(), "ops".to_string()],
            claims: vec!["groups:eng".to_string(), "groups:ops".to_string()],
        };

        let entity = build_cedar_entity(&CedarPrincipal::Oidc(oidc)).unwrap();
        // Verify entity UID
        let uid = entity.uid();
        assert!(uid.to_string().contains("OidcIdentity"));
        assert!(uid.to_string().contains("alice@example.com"));
    }

    #[test]
    fn test_build_cedar_entity_aws() {
        let aws = AwsRoleEntity {
            account_id: "111222333444".to_string(),
            role_arn: "arn:aws:iam::111222333444:role/test-role".to_string(),
            role_name: "test-role".to_string(),
            role_path: "/".to_string(),
        };

        let entity = build_cedar_entity(&CedarPrincipal::AwsRole(aws)).unwrap();
        let uid = entity.uid();
        assert!(uid.to_string().contains("AwsRoleIdentity"));
        assert!(uid.to_string().contains("arn:aws:iam::111222333444:role/test-role"));
    }

    #[test]
    fn test_build_cedar_entity_gcp() {
        let gcp = GcpWorkloadEntity {
            project_id: "proj-1".to_string(),
            email: "sa@proj-1.iam.gserviceaccount.com".to_string(),
            zone: "us-west1-a".to_string(),
        };

        let entity = build_cedar_entity(&CedarPrincipal::GcpWorkload(gcp)).unwrap();
        let uid = entity.uid();
        assert!(uid.to_string().contains("GcpIdentity"));
        assert!(uid.to_string().contains("sa@proj-1.iam.gserviceaccount.com"));
    }

    #[test]
    fn test_principal_entity_uid_oidc() {
        let oidc = OidcEntity {
            email: "test@example.com".to_string(),
            idp_prefix: "azure".to_string(),
            subject: "sub-1".to_string(),
            subject_type: "human".to_string(),
            groups: vec![],
            claims: vec![],
        };

        let uid = principal_entity_uid(&CedarPrincipal::Oidc(oidc)).unwrap();
        assert!(uid.to_string().contains("OidcIdentity"));
        assert!(uid.to_string().contains("test@example.com"));
    }

    #[test]
    fn test_principal_entity_uid_aws() {
        let aws = AwsRoleEntity {
            account_id: "999888777666".to_string(),
            role_arn: "arn:aws:iam::999888777666:role/my-role".to_string(),
            role_name: "my-role".to_string(),
            role_path: "/".to_string(),
        };

        let uid = principal_entity_uid(&CedarPrincipal::AwsRole(aws)).unwrap();
        assert!(uid.to_string().contains("AwsRoleIdentity"));
    }

    #[test]
    fn test_principal_entity_uid_gcp() {
        let gcp = GcpWorkloadEntity {
            project_id: "proj".to_string(),
            email: "sa@proj.iam.gserviceaccount.com".to_string(),
            zone: "zone-a".to_string(),
        };

        let uid = principal_entity_uid(&CedarPrincipal::GcpWorkload(gcp)).unwrap();
        assert!(uid.to_string().contains("GcpIdentity"));
    }

    #[test]
    fn test_build_identity_context_oidc() {
        let identity = AuthenticatedIdentity::Oidc(make_oidc_identity());

        let context = build_identity_context(
            &identity,
            "production",
            "us-east-1",
            "2024-01-01T00:00:00Z",
            &[],
        );

        assert!(context.is_ok());
    }

    #[test]
    fn test_build_identity_context_aws() {
        let identity = AuthenticatedIdentity::AwsSts(make_aws_identity());

        let context = build_identity_context(
            &identity,
            "staging",
            "eu-west-1",
            "2024-06-15T12:00:00Z",
            &["selector-1".to_string()],
        );

        assert!(context.is_ok());
    }

    #[test]
    fn test_build_identity_context_gcp() {
        let identity = AuthenticatedIdentity::Gcp(make_gcp_identity());

        let context = build_identity_context(
            &identity,
            "development",
            "us-west-2",
            "2024-03-20T08:30:00Z",
            &[],
        );

        assert!(context.is_ok());
    }

    #[test]
    fn test_build_identity_context_spire() {
        let identity = AuthenticatedIdentity::Spire(make_spire_identity());
        let selectors = vec!["k8s:ns:finance".to_string()];

        let context = build_identity_context(
            &identity,
            "production",
            "us-east-1",
            "2024-01-01T00:00:00Z",
            &selectors,
        );

        assert!(context.is_ok());
    }
}
