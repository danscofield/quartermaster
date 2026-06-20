// Local Cedar authorizer (uses cedar-policy crate directly)

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};
use tokio::sync::RwLock;

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

/// BatchAuthzRequest contains the parameters for a batch authorization evaluation.
#[derive(Debug, Clone)]
pub struct BatchAuthzRequest {
    pub principal: WorkloadEntity,
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
    /// Evaluates multiple authorization requests for workload billet assumption.
    async fn batch_is_authorized(
        &self,
        req: BatchAuthzRequest,
    ) -> Result<Vec<AuthzDecision>, CedarError>;

    /// Evaluates whether any of the caller's billets permit the admin action.
    async fn is_authorized_admin(&self, req: AdminAuthzRequest) -> Result<bool, CedarError>;
}

/// CedarAuthorizer implements LocalAuthorizer using the cedar-policy crate.
/// Holds an `Arc<RwLock<Option<PolicySet>>>` provided by PolicySyncService for evaluation.
/// No network calls on the evaluation path — all in-process.
pub struct CedarAuthorizer {
    policy_set: Arc<RwLock<Option<PolicySet>>>,
}

impl CedarAuthorizer {
    /// Create a new CedarAuthorizer with the shared policy set reference.
    pub fn new(policy_set: Arc<RwLock<Option<PolicySet>>>) -> Self {
        Self { policy_set }
    }
}

/// Namespace for all Quartermaster Cedar entity types.
const NAMESPACE: &str = "Quartermaster";

/// Maps a PlatformType to the Cedar entity type name string.
fn platform_entity_type_name(platform: &PlatformType) -> &'static str {
    match platform {
        PlatformType::Base => "Workload",
        PlatformType::K8s => "K8sWorkload",
        PlatformType::Ec2 => "Ec2Workload",
        PlatformType::Gcp => "GcpWorkload",
    }
}

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

/// Builds the Cedar Context from a CommonContext.
fn build_context(ctx: &CommonContext) -> Result<Context, CedarError> {
    let pairs = vec![
        ("environment".to_string(), RestrictedExpression::new_string(ctx.environment.clone())),
        ("region".to_string(), RestrictedExpression::new_string(ctx.region.clone())),
        ("request_time".to_string(), RestrictedExpression::new_string(ctx.request_time.clone())),
        ("source_cloud".to_string(), RestrictedExpression::new_string(ctx.source_cloud.clone())),
        ("selectors".to_string(), string_set_expr(&ctx.selectors)),
    ];

    Context::from_pairs(pairs)
        .map_err(|e| CedarError::EvaluationFailed(format!("Failed to build context: {e}")))
}

/// Builds the Cedar Entity for the workload principal, including parent hierarchy.
/// Returns the entities needed for the principal side (platform-specific + base Workload parent).
fn build_workload_entities(workload: &WorkloadEntity) -> Result<Vec<Entity>, CedarError> {
    let platform_type_name = platform_entity_type_name(&workload.entity_type);
    let principal_uid = make_entity_uid(platform_type_name, &workload.spiffe_id)?;

    // Build attributes for the workload entity
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert(
        "spiffe_id".to_string(),
        RestrictedExpression::new_string(workload.spiffe_id.clone()),
    );
    attrs.insert(
        "trust_domain".to_string(),
        RestrictedExpression::new_string(workload.trust_domain.clone()),
    );
    attrs.insert(
        "environment".to_string(),
        RestrictedExpression::new_string(workload.environment.clone()),
    );
    attrs.insert(
        "region".to_string(),
        RestrictedExpression::new_string(workload.region.clone()),
    );
    attrs.insert("selectors".to_string(), string_set_expr(&workload.selectors));

    // Add platform-specific attributes
    match workload.entity_type {
        PlatformType::K8s => {
            attrs.insert(
                "namespace".to_string(),
                RestrictedExpression::new_string(
                    workload.namespace.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "service_account".to_string(),
                RestrictedExpression::new_string(
                    workload.service_account.clone().unwrap_or_default(),
                ),
            );
            attrs.insert("pod_labels".to_string(), string_set_expr(&workload.pod_labels));
            attrs.insert(
                "container_name".to_string(),
                RestrictedExpression::new_string(
                    workload.container_name.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "node_name".to_string(),
                RestrictedExpression::new_string(
                    workload.node_name.clone().unwrap_or_default(),
                ),
            );
        }
        PlatformType::Ec2 => {
            attrs.insert(
                "instance_id".to_string(),
                RestrictedExpression::new_string(
                    workload.instance_id.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "account_id".to_string(),
                RestrictedExpression::new_string(
                    workload.account_id.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "ami_id".to_string(),
                RestrictedExpression::new_string(workload.ami_id.clone().unwrap_or_default()),
            );
            attrs.insert("instance_tags".to_string(), string_set_expr(&workload.instance_tags));
            attrs.insert(
                "security_groups".to_string(),
                string_set_expr(&workload.security_groups),
            );
        }
        PlatformType::Gcp => {
            attrs.insert(
                "project_id".to_string(),
                RestrictedExpression::new_string(
                    workload.project_id.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "zone".to_string(),
                RestrictedExpression::new_string(workload.zone.clone().unwrap_or_default()),
            );
            attrs.insert(
                "service_account_email".to_string(),
                RestrictedExpression::new_string(
                    workload.service_account_email.clone().unwrap_or_default(),
                ),
            );
            attrs.insert(
                "instance_name".to_string(),
                RestrictedExpression::new_string(
                    workload.instance_name.clone().unwrap_or_default(),
                ),
            );
        }
        PlatformType::Base => {
            // Base Workload has only common attributes (already added above)
        }
    }

    let mut entities = Vec::new();

    // If this is a platform-specific workload, register parent hierarchy
    if workload.entity_type != PlatformType::Base {
        // Create the base Workload parent entity (bare, no attrs needed for hierarchy)
        let parent_uid = make_entity_uid("Workload", &workload.spiffe_id)?;
        let parent_entity = Entity::new_no_attrs(parent_uid.clone(), HashSet::new());
        entities.push(parent_entity);

        // Create the platform-specific entity with parent reference
        let parents: HashSet<EntityUid> = HashSet::from([parent_uid]);
        let principal_entity = Entity::new(principal_uid, attrs, parents).map_err(|e| {
            CedarError::EvaluationFailed(format!("Failed to create principal entity: {e}"))
        })?;
        entities.push(principal_entity);
    } else {
        // Base Workload — no parent
        let principal_entity = Entity::new(principal_uid, attrs, HashSet::new()).map_err(|e| {
            CedarError::EvaluationFailed(format!("Failed to create principal entity: {e}"))
        })?;
        entities.push(principal_entity);
    }

    Ok(entities)
}

#[async_trait::async_trait]
impl LocalAuthorizer for CedarAuthorizer {
    async fn batch_is_authorized(
        &self,
        req: BatchAuthzRequest,
    ) -> Result<Vec<AuthzDecision>, CedarError> {
        // Acquire read lock on PolicySet
        let policy_set_guard = self.policy_set.read().await;
        let policy_set = policy_set_guard
            .as_ref()
            .ok_or(CedarError::PolicySetNotInitialized)?;

        let authorizer = Authorizer::new();
        let platform_type_name = platform_entity_type_name(&req.principal.entity_type);
        let principal_uid = make_entity_uid(platform_type_name, &req.principal.spiffe_id)?;
        let action_uid = make_entity_uid("Action", &req.action)?;

        // Build workload entities once (shared across all resource evaluations)
        let workload_entities = build_workload_entities(&req.principal)?;

        let mut decisions = Vec::with_capacity(req.resources.len());

        for resource_name in &req.resources {
            // Construct the billet resource entity (bare entity ID)
            let resource_uid = make_entity_uid("Billet", resource_name)?;
            let billet_entity = Entity::new_no_attrs(resource_uid.clone(), HashSet::new());

            // Combine workload entities + billet entity into Entities set
            let mut all_entities: Vec<Entity> = workload_entities.clone();
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

    async fn is_authorized_admin(&self, req: AdminAuthzRequest) -> Result<bool, CedarError> {
        // Acquire read lock on PolicySet
        let policy_set_guard = self.policy_set.read().await;
        let policy_set = policy_set_guard
            .as_ref()
            .ok_or(CedarError::PolicySetNotInitialized)?;

        let authorizer = Authorizer::new();
        let action_uid = make_entity_uid("Action", &req.action)?;
        let resource_uid = make_entity_uid("Billet", &req.resource)?;

        for billet_name in &req.principals {
            let principal_uid = make_entity_uid("Billet", billet_name)?;

            // Create minimal entities: principal billet + resource billet (bare entity IDs)
            let principal_entity =
                Entity::new_no_attrs(principal_uid.clone(), HashSet::new());
            let resource_entity = Entity::new_no_attrs(resource_uid.clone(), HashSet::new());

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

    fn make_common_context() -> CommonContext {
        CommonContext {
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            request_time: "2024-01-01T00:00:00Z".to_string(),
            source_cloud: "aws".to_string(),
            selectors: vec!["k8s:ns:finance".to_string()],
        }
    }

    fn make_workload_entity() -> WorkloadEntity {
        WorkloadEntity {
            entity_type: PlatformType::K8s,
            spiffe_id: "spiffe://example.com/ns/finance/workload/payments".to_string(),
            trust_domain: "example.com".to_string(),
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            selectors: vec!["k8s:ns:finance".to_string(), "k8s:sa:payments-sa".to_string()],
            namespace: Some("finance".to_string()),
            service_account: Some("payments-sa".to_string()),
            pod_labels: vec!["project:payments".to_string()],
            container_name: Some("main".to_string()),
            node_name: Some("node-1".to_string()),
            instance_id: None,
            account_id: None,
            ami_id: None,
            instance_tags: vec![],
            security_groups: vec![],
            project_id: None,
            zone: None,
            service_account_email: None,
            instance_name: None,
        }
    }

    #[tokio::test]
    async fn test_policy_set_not_initialized() {
        let policy_set = Arc::new(RwLock::new(None));
        let authorizer = CedarAuthorizer::new(policy_set);

        let req = BatchAuthzRequest {
            principal: make_workload_entity(),
            action: "assumeBillet".to_string(),
            resources: vec!["test-billet".to_string()],
            context: make_common_context(),
        };

        let result = authorizer.batch_is_authorized(req).await;
        assert!(matches!(result, Err(CedarError::PolicySetNotInitialized)));
    }

    #[tokio::test]
    async fn test_admin_policy_set_not_initialized() {
        let policy_set = Arc::new(RwLock::new(None));
        let authorizer = CedarAuthorizer::new(policy_set);

        let req = AdminAuthzRequest {
            principals: vec!["quartermaster-admin".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req).await;
        assert!(matches!(result, Err(CedarError::PolicySetNotInitialized)));
    }

    #[tokio::test]
    async fn test_batch_deny_with_empty_policy_set() {
        // An empty PolicySet should deny all requests
        let policy_set = PolicySet::new();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared);

        let req = BatchAuthzRequest {
            principal: make_workload_entity(),
            action: "assumeBillet".to_string(),
            resources: vec!["billet-a".to_string(), "billet-b".to_string()],
            context: make_common_context(),
        };

        let result = authorizer.batch_is_authorized(req).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].decision, Decision::Deny);
        assert_eq!(result[1].decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_admin_deny_with_empty_policy_set() {
        let policy_set = PolicySet::new();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared);

        let req = AdminAuthzRequest {
            principals: vec!["quartermaster-admin".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_batch_allow_with_permit_policy() {
        // Create a policy that permits all principals to assumeBillet on any resource
        let policy_str = r#"
            permit(
                principal,
                action == Quartermaster::Action::"assumeBillet",
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared);

        let req = BatchAuthzRequest {
            principal: make_workload_entity(),
            action: "assumeBillet".to_string(),
            resources: vec!["billet-a".to_string(), "billet-b".to_string()],
            context: make_common_context(),
        };

        let result = authorizer.batch_is_authorized(req).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].resource, "billet-a");
        assert_eq!(result[0].decision, Decision::Allow);
        assert_eq!(result[1].resource, "billet-b");
        assert_eq!(result[1].decision, Decision::Allow);
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
        let authorizer = CedarAuthorizer::new(shared);

        let req = AdminAuthzRequest {
            principals: vec!["quartermaster-admin".to_string()],
            action: "createBillet".to_string(),
            resource: "new-billet".to_string(),
            context: make_common_context(),
        };

        let result = authorizer.is_authorized_admin(req).await.unwrap();
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
        let authorizer = CedarAuthorizer::new(shared);

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

        let result = authorizer.is_authorized_admin(req).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_base_workload_entity_no_parent() {
        // Test that a base Workload (no platform) works correctly
        let policy_str = r#"
            permit(
                principal,
                action == Quartermaster::Action::"assumeBillet",
                resource
            );
        "#;
        let policy_set = policy_str.parse::<PolicySet>().unwrap();
        let shared = Arc::new(RwLock::new(Some(policy_set)));
        let authorizer = CedarAuthorizer::new(shared);

        let workload = WorkloadEntity {
            entity_type: PlatformType::Base,
            spiffe_id: "spiffe://example.com/workload/generic".to_string(),
            trust_domain: "example.com".to_string(),
            environment: "staging".to_string(),
            region: "eu-west-1".to_string(),
            selectors: vec![],
            namespace: None,
            service_account: None,
            pod_labels: vec![],
            container_name: None,
            node_name: None,
            instance_id: None,
            account_id: None,
            ami_id: None,
            instance_tags: vec![],
            security_groups: vec![],
            project_id: None,
            zone: None,
            service_account_email: None,
            instance_name: None,
        };

        let req = BatchAuthzRequest {
            principal: workload,
            action: "assumeBillet".to_string(),
            resources: vec!["test-billet".to_string()],
            context: make_common_context(),
        };

        let result = authorizer.batch_is_authorized(req).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].decision, Decision::Allow);
    }
}
