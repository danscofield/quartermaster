// Local Cedar authorizer (uses cedar-policy crate directly)

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};
use tokio::sync::RwLock;

use crate::sync::PolicySyncService;

/// PlatformType identifies the workload platform for entity type selection.
#[derive(Debug, Clone, PartialEq)]
pub enum PlatformType {
    /// Base Workload — no platform-specific selectors detected.
    Base,
    /// K8sWorkload — Kubernetes workload attestor selectors detected.
    K8s,
    /// Ec2Workload — AWS IID attestor selectors detected.
    Ec2,
    /// GcpWorkload — GCP IIT attestor selectors detected.
    Gcp,
}

/// WorkloadEntity represents an ephemeral Quartermaster workload entity for local Cedar evaluation.
/// Constructed fresh at authorization-time from SVID claims and SPIRE selectors.
/// Never persisted.
#[derive(Debug, Clone)]
pub struct WorkloadEntity {
    /// The detected platform type determining the Cedar entity type.
    pub entity_type: PlatformType,

    // Common attributes (present on all entity types)
    pub spiffe_id: String,
    pub trust_domain: String,
    pub environment: String,
    pub region: String,
    pub selectors: Vec<String>,

    // K8s-specific attributes
    pub namespace: Option<String>,
    pub service_account: Option<String>,
    pub pod_labels: Vec<String>,
    pub container_name: Option<String>,
    pub node_name: Option<String>,

    // EC2-specific attributes
    pub instance_id: Option<String>,
    pub account_id: Option<String>,
    pub ami_id: Option<String>,
    pub instance_tags: Vec<String>,
    pub security_groups: Vec<String>,

    // GCP-specific attributes
    pub project_id: Option<String>,
    pub zone: Option<String>,
    pub service_account_email: Option<String>,
    pub instance_name: Option<String>,
}

/// AuthzDecision represents a single authorization decision from local Cedar evaluation.
#[derive(Debug, Clone)]
pub struct AuthzDecision {
    pub resource: String,
    pub decision: Decision,
}

/// EntityBatchAuthzRequest contains parameters for a batch authorization evaluation
/// using pre-built Cedar entities. Supports any principal type (HumanIdentity,
/// AwsRoleIdentity, GcpIdentity, etc.) for the `assumeBillet` action.
#[derive(Debug, Clone)]
pub struct EntityBatchAuthzRequest {
    /// The principal entity UID string (e.g., "Quartermaster::HumanIdentity::\"alice@example.com\"")
    pub principal_type: String,
    /// The principal entity ID (used for constructing the entity UID)
    pub principal_id: String,
    /// Pre-built Cedar entities for the principal (from MultiSourceEntityBuilder)
    pub principal_entities: Vec<Entity>,
    pub action: String,
    pub resources: Vec<String>,
    pub context: CommonContext,
}

/// CommonContext mirrors the Cedar CommonContext type.
#[derive(Debug, Clone)]
pub struct CommonContext {
    pub environment: String,
    pub region: String,
    pub request_time: String,
    pub source_type: String,
    pub source_cloud: String,
    pub selectors: Vec<String>,
}

/// AdminAuthzRequest contains the parameters for an admin authorization evaluation.
#[derive(Debug, Clone)]
pub struct AdminAuthzRequest {
    pub principals: Vec<String>,
    pub action: String,
    pub resource: String,
    pub context: CommonContext,
}

/// CedarError represents errors from local Cedar policy evaluation.
#[derive(Debug)]
pub enum CedarError {
    PolicySetNotInitialized,
    EvaluationFailed(String),
}

impl std::fmt::Display for CedarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CedarError::PolicySetNotInitialized => write!(f, "PolicySet not initialized"),
            CedarError::EvaluationFailed(msg) => write!(f, "Evaluation failed: {msg}"),
        }
    }
}

impl std::error::Error for CedarError {}

/// LocalAuthorizer provides Cedar policy evaluation using the cedar-policy crate directly.
/// PolicySet is maintained by the PolicySyncService; evaluation is in-process with no network calls.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait LocalAuthorizer: Send + Sync {
    /// Evaluates multiple authorization requests using pre-built Cedar entities.
    /// Supports any principal type (HumanIdentity, AwsRoleIdentity, GcpIdentity)
    /// for the `assumeBillet` action.
    async fn batch_is_authorized_entity(
        &self,
        req: EntityBatchAuthzRequest,
        billet_tags: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<AuthzDecision>, CedarError>;

    /// Evaluates whether any of the caller's billets permit the admin action.
    async fn is_authorized_admin(
        &self,
        req: AdminAuthzRequest,
        billet_tags: &HashMap<String, Vec<String>>,
    ) -> Result<bool, CedarError>;
}

/// CedarAuthorizer implements LocalAuthorizer using the cedar-policy crate.
/// Holds an `Arc<RwLock<Option<PolicySet>>>` provided by PolicySyncService for evaluation.
/// No network calls on the evaluation path — all in-process.
pub struct CedarAuthorizer {
    policy_set: Arc<RwLock<Option<PolicySet>>>,
    policy_sync: Arc<PolicySyncService>,
    system_billets: Vec<String>,
}

impl CedarAuthorizer {
    /// Create a new CedarAuthorizer with the shared policy set reference and PolicySyncService.
    pub fn new(policy_set: Arc<RwLock<Option<PolicySet>>>, policy_sync: Arc<PolicySyncService>, system_billets: Vec<String>) -> Self {
        Self { policy_set, policy_sync, system_billets }
    }

    /// Build a billet tags HashMap by resolving tags from PolicySyncService for each billet name.
    /// If the caller-provided map is non-empty it is used as-is (test override);
    /// otherwise tags are resolved from the cached billet metadata.
    async fn resolve_billet_tags(
        &self,
        caller_tags: &HashMap<String, Vec<String>>,
        billet_names: &[&str],
    ) -> HashMap<String, Vec<String>> {
        if !caller_tags.is_empty() {
            return caller_tags.clone();
        }
        let mut map = HashMap::new();
        for name in billet_names {
            let tags = self.policy_sync.billet_tags(name).await;
            if !tags.is_empty() {
                map.insert(name.to_string(), tags);
            }
        }
        map
    }
}

/// Namespace for all Quartermaster Cedar entity types.
const NAMESPACE: &str = "Quartermaster";

/// Constructs a Cedar EntityUid for a given entity type and ID within the Quartermaster namespace.
fn make_entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, CedarError> {
    let type_name = EntityTypeName::from_str(&format!("{NAMESPACE}::{entity_type}"))
        .map_err(|e| CedarError::EvaluationFailed(format!("Invalid entity type name: {e}")))?;
    let entity_id = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Helper: create a RestrictedExpression for a Set of strings.
fn string_set_expr(values: &[String]) -> RestrictedExpression {
    RestrictedExpression::new_set(
        values.iter().map(|s| RestrictedExpression::new_string(s.clone())),
    )
}

/// Builds a Cedar Entity for a Billet resource (or principal) with a `tags` attribute.
/// The `tags` attribute is a Cedar `Set<String>` containing the billet's tags.
/// If `tags` is empty, the entity still carries an empty set for the attribute.
pub(crate) fn build_billet_entity(name: &str, tags: &[String]) -> Result<Entity, CedarError> {
    let uid = make_entity_uid("Billet", name)?;
    let attrs = HashMap::from([("tags".to_string(), string_set_expr(tags))]);
    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| CedarError::EvaluationFailed(format!("Failed to create billet entity: {e}")))
}

/// Builds the Cedar Context from a CommonContext.
fn build_context(ctx: &CommonContext) -> Result<Context, CedarError> {
    let pairs = vec![
        ("environment".to_string(), RestrictedExpression::new_string(ctx.environment.clone())),
        ("region".to_string(), RestrictedExpression::new_string(ctx.region.clone())),
        ("request_time".to_string(), RestrictedExpression::new_string(ctx.request_time.clone())),
        ("source_type".to_string(), RestrictedExpression::new_string(ctx.source_type.clone())),
        ("source_cloud".to_string(), RestrictedExpression::new_string(ctx.source_cloud.clone())),
        ("selectors".to_string(), string_set_expr(&ctx.selectors)),
    ];

    Context::from_pairs(pairs)
        .map_err(|e| CedarError::EvaluationFailed(format!("Failed to build context: {e}")))
}

/// Builds Cedar entities for a workload authenticated via path pattern extraction.
/// Bypasses WorkloadEntity entirely — constructs the Cedar Entity directly from captures.
///
/// Entity type is always Quartermaster::Workload (no platform subtypes, no parent hierarchy).
/// Attributes: spiffe_id, trust_domain, plus all key-value pairs from captures.
/// Selectors: always empty (no SPIRE API call).
pub fn build_workload_entities_from_captures(
    spiffe_id: &str,
    trust_domain: &str,
    captures: &HashMap<String, String>,
) -> Result<Vec<Entity>, CedarError> {
    let principal_uid = make_entity_uid("Workload", spiffe_id)?;

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert(
        "spiffe_id".to_string(),
        RestrictedExpression::new_string(spiffe_id.to_string()),
    );
    attrs.insert(
        "trust_domain".to_string(),
        RestrictedExpression::new_string(trust_domain.to_string()),
    );

    // Add all captured attributes as String values
    for (name, value) in captures {
        attrs.insert(
            name.clone(),
            RestrictedExpression::new_string(value.clone()),
        );
    }

    // No parent hierarchy — path-pattern entities are always base Workload
    // Empty selectors set (no SPIRE API call in path-pattern mode)
    let entity = Entity::new(principal_uid, attrs, HashSet::new())
        .map_err(|e| CedarError::EvaluationFailed(format!("Failed to create entity: {e}")))?;

    Ok(vec![entity])
}

#[async_trait::async_trait]
impl LocalAuthorizer for CedarAuthorizer {
    async fn batch_is_authorized_entity(
        &self,
        req: EntityBatchAuthzRequest,
        billet_tags: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<AuthzDecision>, CedarError> {
        // Resolve billet tags from PolicySyncService (or use caller-provided tags for testing)
        let resource_names: Vec<&str> = req.resources.iter().map(|s| s.as_str()).collect();
        let resolved_tags = self.resolve_billet_tags(billet_tags, &resource_names).await;

        // Acquire read lock on PolicySet
        let policy_set_guard = self.policy_set.read().await;
        let policy_set = policy_set_guard
            .as_ref()
            .ok_or(CedarError::PolicySetNotInitialized)?;

        let authorizer = Authorizer::new();
        let principal_uid = make_entity_uid(&req.principal_type, &req.principal_id)?;
        let action_uid = make_entity_uid("Action", &req.action)?;

        let mut decisions = Vec::with_capacity(req.resources.len());

        for resource_name in &req.resources {
            // Construct the billet resource entity with tags
            let empty_tags = vec![];
            let tags = resolved_tags.get(resource_name.as_str()).unwrap_or(&empty_tags);
            let billet_entity = build_billet_entity(resource_name, tags)?;
            let resource_uid = make_entity_uid("Billet", resource_name)?;

            // Combine pre-built principal entities + billet entity into Entities set
            let mut all_entities: Vec<Entity> = req.principal_entities.clone();
            all_entities.push(billet_entity);

            let entities = Entities::from_entities(all_entities, None).map_err(|e| {
                CedarError::EvaluationFailed(format!("Failed to build entities: {e}"))
            })?;

            // Build context
            let context = build_context(&req.context)?;

            // Construct the Cedar Request
            let request = Request::new(
                principal_uid.clone(),
                action_uid.clone(),
                resource_uid,
                context,
                None, // No schema validation on request
            )
            .map_err(|e| {
                CedarError::EvaluationFailed(format!("Failed to build request: {e}"))
            })?;

            // Evaluate
            let response = authorizer.is_authorized(&request, policy_set, &entities);

            decisions.push(AuthzDecision {
                resource: resource_name.clone(),
                decision: response.decision(),
            });
        }

        Ok(decisions)
    }

    async fn is_authorized_admin(
        &self,
        req: AdminAuthzRequest,
        billet_tags: &HashMap<String, Vec<String>>,
    ) -> Result<bool, CedarError> {
        // System billets are immune to lockout on admin actions (root model)
        if req.principals.iter().any(|p| self.system_billets.iter().any(|s| s == p)) {
            return Ok(true);
        }

        // Resolve billet tags from PolicySyncService for all relevant billets
        // (principals + resource)
        let mut all_billet_names: Vec<&str> = req.principals.iter().map(|s| s.as_str()).collect();
        all_billet_names.push(req.resource.as_str());
        let resolved_tags = self.resolve_billet_tags(billet_tags, &all_billet_names).await;

        // Acquire read lock on PolicySet
        let policy_set_guard = self.policy_set.read().await;
        let policy_set = policy_set_guard
            .as_ref()
            .ok_or(CedarError::PolicySetNotInitialized)?;

        let authorizer = Authorizer::new();
        let action_uid = make_entity_uid("Action", &req.action)?;
        let resource_uid = make_entity_uid("Billet", &req.resource)?;

        let empty_tags = vec![];

        for billet_name in &req.principals {
            // Build enriched principal billet entity with tags
            let principal_tags = resolved_tags.get(billet_name.as_str()).unwrap_or(&empty_tags);
            let principal_entity = build_billet_entity(billet_name, principal_tags)?;
            let principal_uid = make_entity_uid("Billet", billet_name)?;

            // Build enriched resource billet entity with tags
            let resource_tags = resolved_tags.get(req.resource.as_str()).unwrap_or(&empty_tags);
            let resource_entity = build_billet_entity(&req.resource, resource_tags)?;

            let entities =
                Entities::from_entities(vec![principal_entity, resource_entity], None).map_err(
                    |e| CedarError::EvaluationFailed(format!("Failed to build entities: {e}")),
                )?;

            // Build context for each evaluation
            let ctx = build_context(&req.context)?;

            let request = Request::new(
                principal_uid,
                action_uid.clone(),
                resource_uid.clone(),
                ctx,
                None,
            )
            .map_err(|e| {
                CedarError::EvaluationFailed(format!("Failed to build request: {e}"))
            })?;

            let response = authorizer.is_authorized(&request, policy_set, &entities);

            if response.decision() == Decision::Allow {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::service::AuditService;
    use crate::datastore::MockDataStore;

    fn test_audit_service() -> AuditService {
        AuditService::new(vec![], 100)
    }

    /// Creates a minimal PolicySyncService for tests (uninitialized — returns empty tags).
    /// Tests pass billet_tags explicitly through the caller parameter, so the PolicySyncService
    /// is only needed to satisfy the struct field.
    fn test_policy_sync() -> Arc<PolicySyncService> {
        let mock_dynamo = MockDataStore::new();
        Arc::new(PolicySyncService::new(Arc::new(mock_dynamo), 300, test_audit_service()))
    }

    fn make_common_context() -> CommonContext {
        CommonContext {
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            request_time: "2024-01-01T00:00:00Z".to_string(),
            source_type: "spire".to_string(),
            source_cloud: "aws".to_string(),
            selectors: vec!["k8s:ns:finance".to_string()],
        }
    }

    #[tokio::test]
    async fn test_admin_policy_set_not_initialized() {
        let policy_set = Arc::new(RwLock::new(None));
        let authorizer = CedarAuthorizer::new(policy_set, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let req = AdminAuthzRequest {
            principals: vec!["some-non-system-billet".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req, &HashMap::new()).await;
        assert!(matches!(result, Err(CedarError::PolicySetNotInitialized)));
    }

    #[tokio::test]
    async fn test_admin_deny_with_empty_policy_set() {
        let policy_set = PolicySet::new();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let req = AdminAuthzRequest {
            principals: vec!["some-non-system-billet".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req, &HashMap::new()).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_admin_allow_with_permit_policy() {
        // Create a policy that permits the admin billet to do anything
        let policy_str = r#"
            permit(
                principal == Quartermaster::Billet::"quartermaster-admin",
                action,
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let req = AdminAuthzRequest {
            principals: vec!["quartermaster-admin".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req, &HashMap::new()).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_admin_allow_if_any_billet_authorized() {
        // Only quartermaster-admin is authorized
        let policy_str = r#"
            permit(
                principal == Quartermaster::Billet::"quartermaster-admin",
                action,
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        // Include a non-admin billet and the admin billet — should allow because admin is present
        let req = AdminAuthzRequest {
            principals: vec![
                "some-other-billet".to_string(),
                "quartermaster-admin".to_string(),
            ],
            action: "deleteBillet".to_string(),
            resource: "target-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req, &HashMap::new()).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_batch_entity_allow_human_identity() {
        // Policy that allows HumanIdentity principals to assumeBillet
        let policy_str = r#"
            permit(
                principal is Quartermaster::HumanIdentity,
                action == Quartermaster::Action::"assumeBillet",
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        // Build a HumanIdentity entity
        let principal_uid = make_entity_uid("HumanIdentity", "alice@example.com").unwrap();
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "email".to_string(),
            RestrictedExpression::new_string("alice@example.com".to_string()),
        );
        attrs.insert(
            "idp_prefix".to_string(),
            RestrictedExpression::new_string("okta".to_string()),
        );
        attrs.insert(
            "groups".to_string(),
            string_set_expr(&["engineering".to_string(), "billing-ops".to_string()]),
        );
        let human_entity = Entity::new(principal_uid, attrs, HashSet::new()).unwrap();

        let req = EntityBatchAuthzRequest {
            principal_type: "HumanIdentity".to_string(),
            principal_id: "alice@example.com".to_string(),
            principal_entities: vec![human_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["billing-writer".to_string()],
            context: CommonContext {
                environment: "production".to_string(),
                region: "us-east-1".to_string(),
                request_time: "2024-01-01T00:00:00Z".to_string(),
                source_type: "oidc".to_string(),
                source_cloud: "".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].decision, Decision::Allow);
        assert_eq!(result[0].resource, "billing-writer");
    }

    #[tokio::test]
    async fn test_batch_entity_allow_aws_role_identity() {
        // Policy that allows AwsRoleIdentity principals to assumeBillet
        let policy_str = r#"
            permit(
                principal is Quartermaster::AwsRoleIdentity,
                action == Quartermaster::Action::"assumeBillet",
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let principal_uid = make_entity_uid(
            "AwsRoleIdentity",
            "arn:aws:iam::123456789012:role/billing-service",
        )
        .unwrap();
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "account_id".to_string(),
            RestrictedExpression::new_string("123456789012".to_string()),
        );
        attrs.insert(
            "role_arn".to_string(),
            RestrictedExpression::new_string(
                "arn:aws:iam::123456789012:role/billing-service".to_string(),
            ),
        );
        attrs.insert(
            "role_name".to_string(),
            RestrictedExpression::new_string("billing-service".to_string()),
        );
        attrs.insert(
            "role_path".to_string(),
            RestrictedExpression::new_string("/".to_string()),
        );
        let aws_entity = Entity::new(principal_uid, attrs, HashSet::new()).unwrap();

        let req = EntityBatchAuthzRequest {
            principal_type: "AwsRoleIdentity".to_string(),
            principal_id: "arn:aws:iam::123456789012:role/billing-service".to_string(),
            principal_entities: vec![aws_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["payments".to_string()],
            context: CommonContext {
                environment: "production".to_string(),
                region: "us-east-1".to_string(),
                request_time: "2024-01-01T00:00:00Z".to_string(),
                source_type: "aws-sts".to_string(),
                source_cloud: "aws".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_batch_entity_allow_gcp_identity() {
        // Policy that allows GcpIdentity principals to assumeBillet
        let policy_str = r#"
            permit(
                principal is Quartermaster::GcpIdentity,
                action == Quartermaster::Action::"assumeBillet",
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let principal_uid = make_entity_uid(
            "GcpIdentity",
            "sa@my-project.iam.gserviceaccount.com",
        )
        .unwrap();
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "project_id".to_string(),
            RestrictedExpression::new_string("my-project".to_string()),
        );
        attrs.insert(
            "email".to_string(),
            RestrictedExpression::new_string(
                "sa@my-project.iam.gserviceaccount.com".to_string(),
            ),
        );
        attrs.insert(
            "zone".to_string(),
            RestrictedExpression::new_string("us-central1-a".to_string()),
        );
        let gcp_entity = Entity::new(principal_uid, attrs, HashSet::new()).unwrap();

        let req = EntityBatchAuthzRequest {
            principal_type: "GcpIdentity".to_string(),
            principal_id: "sa@my-project.iam.gserviceaccount.com".to_string(),
            principal_entities: vec![gcp_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["analytics".to_string(), "reporting".to_string()],
            context: CommonContext {
                environment: "staging".to_string(),
                region: "us-west-2".to_string(),
                request_time: "2024-06-15T12:00:00Z".to_string(),
                source_type: "gcp".to_string(),
                source_cloud: "gcp".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].decision, Decision::Allow);
        assert_eq!(result[1].decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_batch_entity_deny_with_empty_policy_set() {
        let policy_set = PolicySet::new();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let principal_uid = make_entity_uid("HumanIdentity", "bob@example.com").unwrap();
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "email".to_string(),
            RestrictedExpression::new_string("bob@example.com".to_string()),
        );
        attrs.insert(
            "idp_prefix".to_string(),
            RestrictedExpression::new_string("azure".to_string()),
        );
        attrs.insert("groups".to_string(), string_set_expr(&[]));
        let human_entity = Entity::new(principal_uid, attrs, HashSet::new()).unwrap();

        let req = EntityBatchAuthzRequest {
            principal_type: "HumanIdentity".to_string(),
            principal_id: "bob@example.com".to_string(),
            principal_entities: vec![human_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["secret-billet".to_string()],
            context: CommonContext {
                environment: "production".to_string(),
                region: "us-east-1".to_string(),
                request_time: "2024-01-01T00:00:00Z".to_string(),
                source_type: "oidc".to_string(),
                source_cloud: "".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_batch_entity_policy_set_not_initialized() {
        let shared = Arc::new(RwLock::new(None));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let principal_uid = make_entity_uid("HumanIdentity", "test@test.com").unwrap();
        let human_entity = Entity::new_no_attrs(principal_uid, HashSet::new());

        let req = EntityBatchAuthzRequest {
            principal_type: "HumanIdentity".to_string(),
            principal_id: "test@test.com".to_string(),
            principal_entities: vec![human_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["any-billet".to_string()],
            context: CommonContext {
                environment: "".to_string(),
                region: "".to_string(),
                request_time: "".to_string(),
                source_type: "oidc".to_string(),
                source_cloud: "".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await;
        assert!(matches!(result, Err(CedarError::PolicySetNotInitialized)));
    }

    #[tokio::test]
    async fn test_context_includes_source_type() {
        // Policy that conditions on source_type in context
        let policy_str = r#"
            permit(
                principal,
                action == Quartermaster::Action::"assumeBillet",
                resource
            ) when {
                context.source_type == "oidc"
            };
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared, test_policy_sync(), vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]);

        let principal_uid = make_entity_uid("HumanIdentity", "user@example.com").unwrap();
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "email".to_string(),
            RestrictedExpression::new_string("user@example.com".to_string()),
        );
        attrs.insert(
            "idp_prefix".to_string(),
            RestrictedExpression::new_string("okta".to_string()),
        );
        attrs.insert("groups".to_string(), string_set_expr(&[]));
        let human_entity = Entity::new(principal_uid, attrs, HashSet::new()).unwrap();

        // Request with source_type = "oidc" — should be allowed
        let req = EntityBatchAuthzRequest {
            principal_type: "HumanIdentity".to_string(),
            principal_id: "user@example.com".to_string(),
            principal_entities: vec![human_entity.clone()],
            action: "assumeBillet".to_string(),
            resources: vec!["test-billet".to_string()],
            context: CommonContext {
                environment: "production".to_string(),
                region: "us-east-1".to_string(),
                request_time: "2024-01-01T00:00:00Z".to_string(),
                source_type: "oidc".to_string(),
                source_cloud: "".to_string(),
                selectors: vec![],
            },
        };

        let result = authorizer.batch_is_authorized_entity(req, &HashMap::new()).await.unwrap();
        assert_eq!(result[0].decision, Decision::Allow);

        // Request with source_type = "spire" — should be denied by the condition
        let req2 = EntityBatchAuthzRequest {
            principal_type: "HumanIdentity".to_string(),
            principal_id: "user@example.com".to_string(),
            principal_entities: vec![human_entity],
            action: "assumeBillet".to_string(),
            resources: vec!["test-billet".to_string()],
            context: CommonContext {
                environment: "production".to_string(),
                region: "us-east-1".to_string(),
                request_time: "2024-01-01T00:00:00Z".to_string(),
                source_type: "spire".to_string(),
                source_cloud: "".to_string(),
                selectors: vec![],
            },
        };

        let result2 = authorizer.batch_is_authorized_entity(req2, &HashMap::new()).await.unwrap();
        assert_eq!(result2[0].decision, Decision::Deny);
    }
}
