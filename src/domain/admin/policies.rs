// Policy CRUD service

use std::sync::Arc;

use cedar_policy::{Effect, EntityUid, PolicySet, ResourceConstraint};
use serde::{Deserialize, Serialize};

use crate::datastore::{DataStore, DataStoreError};

/// Errors that can occur during policy CRUD operations.
#[derive(Debug)]
pub enum PolicyCrudError {
    /// The Cedar statement is syntactically invalid (400).
    InvalidStatement(String),
    /// The resource scope doesn't match the owning billet (400).
    InvalidResourceScope(String),
    /// The owning billet does not exist (404).
    BilletNotFound(String),
    /// The policy was not found (404).
    NotFound(String),
    /// An internal error occurred (500).
    InternalError(String),
}

impl std::fmt::Display for PolicyCrudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyCrudError::InvalidStatement(msg) => {
                write!(f, "invalid Cedar statement: {}", msg)
            }
            PolicyCrudError::InvalidResourceScope(msg) => {
                write!(f, "invalid resource scope: {}", msg)
            }
            PolicyCrudError::BilletNotFound(name) => {
                write!(f, "billet '{}' not found", name)
            }
            PolicyCrudError::NotFound(id) => write!(f, "policy '{}' not found", id),
            PolicyCrudError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyCrudError {}

/// Response returned on successful policy creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCreateResponse {
    pub policy_id: String,
    pub statement: String,
    pub description: String,
    pub created_at: String,
}

/// PolicyCrudService provides policy management logic for the admin control plane.
pub struct PolicyCrudService {
    data_store: Arc<dyn DataStore>,
    system_billets: Vec<String>,
}

impl PolicyCrudService {
    /// Creates a new PolicyCrudService.
    pub fn new(data_store: Arc<dyn DataStore>, system_billets: Vec<String>) -> Self {
        Self { data_store, system_billets }
    }

    /// Returns true if the given billet name is in the system billet exempt list.
    fn is_system_billet(&self, billet_name: &str) -> bool {
        self.system_billets.iter().any(|s| s == billet_name)
    }

    /// Validates that the given statement is a syntactically valid Cedar policy set.
    fn validate_cedar_statement(statement: &str) -> Result<(), PolicyCrudError> {
        statement
            .parse::<PolicySet>()
            .map_err(|e| PolicyCrudError::InvalidStatement(e.to_string()))?;
        Ok(())
    }

    /// Validates that all policies in the statement have `forbid` effect.
    /// Returns an error if any policy has `permit` effect.
    /// Guardrail policies (on the `quartermaster-guardrails` billet) must be forbid-only.
    fn validate_forbid_only(statement: &str) -> Result<(), PolicyCrudError> {
        let policy_set = statement
            .parse::<PolicySet>()
            .map_err(|e| PolicyCrudError::InvalidStatement(e.to_string()))?;

        for policy in policy_set.policies() {
            if policy.effect() == Effect::Permit {
                return Err(PolicyCrudError::InvalidStatement(
                    "guardrail policies must be forbid-only; permit policies are not allowed on the quartermaster-guardrails billet".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validates that the resource scope in the Cedar statement is appropriate for the owning billet.
    ///
    /// For each policy in the statement:
    /// - Rejects unconstrained resource (bare `resource`) — too broad
    /// - Rejects resource scope referencing a different billet
    /// - Accepts `resource == Billet::"<billet_name>"` where billet_name matches the owning billet
    ///
    /// All policies are validated regardless of action.
    pub fn validate_resource_scope(
        statement: &str,
        billet_name: &str,
    ) -> Result<(), PolicyCrudError> {
        let policy_set = statement
            .parse::<PolicySet>()
            .map_err(|e| PolicyCrudError::InvalidStatement(e.to_string()))?;

        for policy in policy_set.policies() {
            match policy.resource_constraint() {
                ResourceConstraint::Any => {
                    return Err(PolicyCrudError::InvalidResourceScope(
                        "policies must specify resource == Billet::<owning billet>; unconstrained resource is not allowed".to_string(),
                    ));
                }
                ResourceConstraint::Eq(ref entity_uid) => {
                    Self::check_resource_entity_uid(entity_uid, billet_name)?;
                }
                ResourceConstraint::In(ref entity_uid) => {
                    Self::check_resource_entity_uid(entity_uid, billet_name)?;
                }
                ResourceConstraint::Is(_) => {
                    return Err(PolicyCrudError::InvalidResourceScope(
                        "policies must use resource == Billet::<owning billet> with the owning billet name".to_string(),
                    ));
                }
                ResourceConstraint::IsIn(_, ref entity_uid) => {
                    Self::check_resource_entity_uid(entity_uid, billet_name)?;
                }
            }
        }

        Ok(())
    }

    /// Validates that a resource EntityUid references the correct owning billet.
    fn check_resource_entity_uid(
        entity_uid: &EntityUid,
        billet_name: &str,
    ) -> Result<(), PolicyCrudError> {
        let type_name = entity_uid.type_name();
        let entity_id = entity_uid.id().unescaped();

        // Check that the type is "Billet" (with or without namespace)
        let basename = type_name.basename();
        if basename != "Billet" {
            return Err(PolicyCrudError::InvalidResourceScope(format!(
                "policy resource must be of type Billet, found '{}'",
                type_name,
            )));
        }

        // Check that the entity ID matches the owning billet
        if entity_id != billet_name {
            return Err(PolicyCrudError::InvalidResourceScope(format!(
                "resource scope references billet '{}' but policy belongs to billet '{}'",
                entity_id, billet_name,
            )));
        }

        Ok(())
    }

    /// Creates a new Cedar policy under a billet.
    ///
    /// 1. Validates Cedar statement syntax
    /// 2. Validates resource scope matches owning billet
    /// 3. Checks billet exists via `get_billet_metadata` — returns BilletNotFound if None
    /// 4. Generates a UUID for the policy_id
    /// 5. Writes to quartermaster-policies DynamoDB table with composite key
    /// 6. Returns PolicyCreateResponse
    pub async fn create(
        &self,
        billet_name: &str,
        statement: &str,
        description: &str,
    ) -> Result<PolicyCreateResponse, PolicyCrudError> {
        // Validate Cedar statement syntax
        Self::validate_cedar_statement(statement)?;

        // Guardrail policies must be forbid-only
        if billet_name == "quartermaster-guardrails" {
            Self::validate_forbid_only(statement)?;
        }

        // Validate resource scope matches owning billet
        // System billets are allowed any resource scope (unconstrained, referencing other billets, etc.)
        if !self.is_system_billet(billet_name) {
            Self::validate_resource_scope(statement, billet_name)?;
        }

        // Verify billet exists
        let billet_record = self
            .data_store
            .get_billet(billet_name)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;
        if billet_record.is_none() {
            return Err(PolicyCrudError::BilletNotFound(billet_name.to_string()));
        }

        // Generate UUID for policy_id
        let policy_id = uuid::Uuid::new_v4().to_string();

        // Build created_at timestamp
        let created_at = chrono::Utc::now().to_rfc3339();

        // Write to DataStore
        let record = crate::datastore::PolicyRecord {
            billet_name: billet_name.to_string(),
            policy_id: policy_id.clone(),
            statement: statement.to_string(),
            description: description.to_string(),
            created_at: created_at.clone(),
            updated_at: created_at.clone(),
        };
        self.data_store
            .create_policy(&record)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;

        Ok(PolicyCreateResponse {
            policy_id,
            statement: statement.to_string(),
            description: description.to_string(),
            created_at,
        })
    }

    /// Lists all policies for a billet.
    ///
    /// Calls `list_policies_for_billet` on the DataStore.
    pub async fn list_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<crate::datastore::PolicyRecord>, PolicyCrudError> {
        let records = self
            .data_store
            .list_policies_for_billet(billet_name)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;

        Ok(records)
    }

    /// Gets a single policy by billet + id.
    ///
    /// Calls `get_policy(billet_name, policy_id)` and returns NotFound if None.
    pub async fn get(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<crate::datastore::PolicyRecord, PolicyCrudError> {
        let record = self
            .data_store
            .get_policy(billet_name, policy_id)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;

        match record {
            Some(r) => Ok(r),
            None => Err(PolicyCrudError::NotFound(policy_id.to_string())),
        }
    }

    /// Updates an existing Cedar policy.
    ///
    /// 1. Validates Cedar statement syntax
    /// 2. Validates resource scope matches owning billet
    /// 3. Updates via DynamoDB with composite key (billet_name + policy_id)
    /// 4. Returns the updated PolicyRecord
    pub async fn update(
        &self,
        billet_name: &str,
        policy_id: &str,
        statement: &str,
        description: &str,
    ) -> Result<crate::datastore::PolicyRecord, PolicyCrudError> {
        // Validate Cedar statement syntax
        Self::validate_cedar_statement(statement)?;

        // Guardrail policies must be forbid-only
        if billet_name == "quartermaster-guardrails" {
            Self::validate_forbid_only(statement)?;
        }

        // Validate resource scope matches owning billet
        // System billets are allowed any resource scope (unconstrained, referencing other billets, etc.)
        if !self.is_system_billet(billet_name) {
            Self::validate_resource_scope(statement, billet_name)?;
        }

        // Update in DataStore
        let updated_record = crate::datastore::PolicyRecord {
            billet_name: billet_name.to_string(),
            policy_id: policy_id.to_string(),
            statement: statement.to_string(),
            description: description.to_string(),
            created_at: String::new(), // will be preserved by update_policy
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        self.data_store
            .update_policy(&updated_record)
            .await
            .map_err(|e| match e {
                DataStoreError::NotFound(_) => PolicyCrudError::NotFound(policy_id.to_string()),
                other => PolicyCrudError::InternalError(other.to_string()),
            })?;

        // Fetch and return the updated record
        let record = self
            .data_store
            .get_policy(billet_name, policy_id)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;

        match record {
            Some(r) => Ok(r),
            None => Err(PolicyCrudError::NotFound(policy_id.to_string())),
        }
    }

    /// Deletes a Cedar policy.
    ///
    /// 1. Calls DataStore::delete_policy with composite key
    /// 2. Maps errors appropriately
    pub async fn delete(&self, billet_name: &str, policy_id: &str) -> Result<(), PolicyCrudError> {
        self.data_store
            .delete_policy(billet_name, policy_id)
            .await
            .map_err(|e| match e {
                DataStoreError::NotFound(_) => PolicyCrudError::NotFound(policy_id.to_string()),
                other => PolicyCrudError::InternalError(other.to_string()),
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::{MockDataStore, PolicyRecord as DsPolicyRecord, BilletRecord};

    /// A valid Cedar policy statement for testing.
    const VALID_STATEMENT: &str = r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#;

    /// An invalid Cedar policy statement for testing.
    const INVALID_STATEMENT: &str = r#"this is not valid cedar syntax{"#;

    /// Default system billets used across tests.
    fn default_system_billets() -> Vec<String> {
        vec![
            "quartermaster-admin".to_string(),
            "quartermaster-guardrails".to_string(),
        ]
    }

    #[tokio::test]
    async fn test_create_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "payments".to_string(),
                    description: "Payments billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });
        mock.expect_create_policy().returning(|_| Ok(()));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.create("payments", VALID_STATEMENT, "Allow payments").await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.statement, VALID_STATEMENT);
        assert_eq!(response.description, "Allow payments");
        // policy_id should be a valid UUID
        assert!(uuid::Uuid::parse_str(&response.policy_id).is_ok());
        // created_at should be non-empty
        assert!(!response.created_at.is_empty());
    }

    #[tokio::test]
    async fn test_create_invalid_statement() {
        let mock = MockDataStore::new();
        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.create("payments", INVALID_STATEMENT, "Bad policy").await;
        assert!(matches!(result, Err(PolicyCrudError::InvalidStatement(_))));
    }

    #[tokio::test]
    async fn test_create_billet_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(None));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.create("payments", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::BilletNotFound(_))));
    }

    #[tokio::test]
    async fn test_create_datastore_error() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "payments".to_string(),
                    description: "".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "".to_string(),
                    updated_at: "".to_string(),
                }))
            });
        mock.expect_create_policy()
            .returning(|_| Err(crate::datastore::DataStoreError::Internal("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.create("payments", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_list_for_billet_success() {
        let mut mock = MockDataStore::new();
        mock.expect_list_policies_for_billet()
            .withf(|name| name == "payments")
            .returning(|_| {
                Ok(vec![
                    DsPolicyRecord {
                        billet_name: "payments".to_string(),
                        policy_id: "p1".to_string(),
                        statement: "permit(...);".to_string(),
                        description: "Policy 1".to_string(),
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    },
                    DsPolicyRecord {
                        billet_name: "payments".to_string(),
                        policy_id: "p2".to_string(),
                        statement: "permit(...);".to_string(),
                        description: "Policy 2".to_string(),
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    },
                ])
            });

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());
        let result = service.list_for_billet("payments").await;
        assert!(result.is_ok());
        let policies = result.unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].policy_id, "p1");
        assert_eq!(policies[1].policy_id, "p2");
    }

    #[tokio::test]
    async fn test_get_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_policy()
            .withf(|billet_name, policy_id| billet_name == "payments" && policy_id == "p1")
            .returning(|_, _| {
                Ok(Some(DsPolicyRecord {
                    billet_name: "payments".to_string(),
                    policy_id: "p1".to_string(),
                    statement: "permit(...);".to_string(),
                    description: "A policy".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());
        let result = service.get("payments", "p1").await;
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.billet_name, "payments");
        assert_eq!(record.policy_id, "p1");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_policy()
            .returning(|_, _| Ok(None));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());
        let result = service.get("payments", "nonexistent").await;
        assert!(matches!(result, Err(PolicyCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_success() {
        let mut mock = MockDataStore::new();
        mock.expect_update_policy()
            .withf(|record| {
                record.billet_name == "payments" && record.policy_id == "policy-123" && record.statement == VALID_STATEMENT && record.description == "Updated"
            })
            .returning(|_| Ok(()));
        mock.expect_get_policy()
            .withf(|billet_name, id| billet_name == "payments" && id == "policy-123")
            .returning(|_, _| {
                Ok(Some(DsPolicyRecord {
                    billet_name: "payments".to_string(),
                    policy_id: "policy-123".to_string(),
                    statement: VALID_STATEMENT.to_string(),
                    description: "Updated".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-02T00:00:00Z".to_string(),
                }))
            });

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.update("payments", "policy-123", VALID_STATEMENT, "Updated").await;
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.policy_id, "policy-123");
        assert_eq!(record.description, "Updated");
    }

    #[tokio::test]
    async fn test_update_invalid_statement() {
        let mock = MockDataStore::new();
        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.update("payments", "policy-123", INVALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InvalidStatement(_))));
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_update_policy()
            .returning(|_| Err(crate::datastore::DataStoreError::NotFound("not found".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.update("payments", "nonexistent", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_datastore_service_error() {
        let mut mock = MockDataStore::new();
        mock.expect_update_policy()
            .returning(|_| Err(crate::datastore::DataStoreError::Internal("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.update("payments", "policy-123", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_delete_success() {
        let mut mock = MockDataStore::new();
        mock.expect_delete_policy()
            .withf(|billet_name, id| billet_name == "payments" && id == "policy-123")
            .returning(|_, _| Ok(()));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.delete("payments", "policy-123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_delete_policy()
            .returning(|_, _| Err(crate::datastore::DataStoreError::NotFound("not found".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.delete("payments", "nonexistent").await;
        assert!(matches!(result, Err(PolicyCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_datastore_service_error() {
        let mut mock = MockDataStore::new();
        mock.expect_delete_policy()
            .returning(|_, _| Err(crate::datastore::DataStoreError::Internal("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock), default_system_billets());

        let result = service.delete("payments", "policy-123").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }

    /// Property-based tests for resource scope validation.
    ///
    /// Uses `proptest` to validate the 5 correctness properties from the design document.
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        /// Valid Cedar actions used in Quartermaster policies.
        const VALID_ACTIONS: &[&str] = &[
            "assumeBillet",
            "createPolicy",
            "updatePolicy",
            "deletePolicy",
            "readBillet",
            "updateBillet",
            "deleteBillet",
        ];

        /// Strategy to generate a random action from the valid set.
        fn action_strategy() -> impl Strategy<Value = String> {
            prop::sample::select(VALID_ACTIONS).prop_map(|s| s.to_string())
        }

        /// Strategy to generate a valid billet name (non-empty alphanumeric + hyphens).
        fn billet_name_strategy() -> impl Strategy<Value = String> {
            "[a-z][a-z0-9\\-]{0,19}".prop_map(|s| s.to_string())
        }

        /// Build a Cedar policy statement with the given action, principal, and resource scope.
        fn build_policy(action: &str, principal: &str, resource: &str) -> String {
            format!(
                r#"permit({}, action == Quartermaster::Action::"{}", {});"#,
                principal, action, resource
            )
        }

        // ─────────────────────────────────────────────────────────────────────
        // Property 1: Valid resource scope passes for any action
        // Feature: principal-scope-validation, Property 1: Valid resource scope passes for any action
        // Validates: Requirements 1.1, 5.2
        // ─────────────────────────────────────────────────────────────────────
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_valid_resource_scope_passes_for_any_action(
                action in action_strategy(),
                billet_name in billet_name_strategy(),
            ) {
                let resource = format!(r#"resource == Quartermaster::Billet::"{}""#, billet_name);
                let statement = build_policy(&action, "principal", &resource);

                let result = PolicyCrudService::validate_resource_scope(&statement, &billet_name);
                prop_assert!(
                    result.is_ok(),
                    "Expected Ok(()) for action={}, billet={}, statement={}, got {:?}",
                    action, billet_name, statement, result
                );
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Property 2: Invalid resource scope rejected for any action
        // Feature: principal-scope-validation, Property 2: Invalid resource scope rejected for any action
        // Validates: Requirements 1.2, 1.3
        // ─────────────────────────────────────────────────────────────────────
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_invalid_resource_scope_rejected_mismatched_billet(
                action in action_strategy(),
                owning_billet in billet_name_strategy(),
                other_billet in billet_name_strategy(),
            ) {
                // Ensure the two billet names are actually different
                prop_assume!(owning_billet != other_billet);

                let resource = format!(r#"resource == Quartermaster::Billet::"{}""#, other_billet);
                let statement = build_policy(&action, "principal", &resource);

                let result = PolicyCrudService::validate_resource_scope(&statement, &owning_billet);
                prop_assert!(
                    matches!(result, Err(PolicyCrudError::InvalidResourceScope(_))),
                    "Expected InvalidResourceScope for mismatched billet, action={}, owning={}, other={}, got {:?}",
                    action, owning_billet, other_billet, result
                );
            }

            #[test]
            fn prop_invalid_resource_scope_rejected_unconstrained(
                action in action_strategy(),
                billet_name in billet_name_strategy(),
            ) {
                let statement = build_policy(&action, "principal", "resource");

                let result = PolicyCrudService::validate_resource_scope(&statement, &billet_name);
                prop_assert!(
                    matches!(result, Err(PolicyCrudError::InvalidResourceScope(_))),
                    "Expected InvalidResourceScope for unconstrained resource, action={}, billet={}, got {:?}",
                    action, billet_name, result
                );
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Property 3: System billet exemption
        // Feature: principal-scope-validation, Property 3: System billet exemption
        // Validates: Requirements 2.1, 2.2, 2.3
        // ─────────────────────────────────────────────────────────────────────
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_system_billet_exemption(
                action in action_strategy(),
                system_billet in prop::sample::select(&["quartermaster-admin", "quartermaster-guardrails"][..]),
                random_billet in billet_name_strategy(),
            ) {
                let system_billets = default_system_billets();
                let mock = MockDataStore::new();
                let service = PolicyCrudService::new(Arc::new(mock), system_billets);

                // is_system_billet must return true for system billets
                prop_assert!(
                    service.is_system_billet(system_billet),
                    "Expected is_system_billet to return true for '{}'",
                    system_billet
                );

                // is_system_billet must return false for random non-system billets
                // (unless the random name happens to match a system billet)
                if random_billet != "quartermaster-admin" && random_billet != "quartermaster-guardrails" {
                    prop_assert!(
                        !service.is_system_billet(&random_billet),
                        "Expected is_system_billet to return false for '{}' but got true",
                        random_billet
                    );
                }

                // Validate that even invalid resource scope statements would be acceptable
                // for system billets (the guard in create/update skips validation).
                // We verify this by showing validate_resource_scope WOULD fail,
                // but the system billet check prevents it from being called.
                let unconstrained_statement = build_policy(&action, "principal", "resource");
                let scope_result = PolicyCrudService::validate_resource_scope(&unconstrained_statement, system_billet);
                // This demonstrates the policy would fail validation...
                prop_assert!(
                    scope_result.is_err(),
                    "Unconstrained resource should fail validate_resource_scope"
                );
                // ...but is_system_billet returns true, so create/update would skip validation
                prop_assert!(service.is_system_billet(system_billet));
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Property 4: Principal is unconstrained
        // Feature: principal-scope-validation, Property 4: Principal is unconstrained
        // Validates: Requirements 4.1, 4.2
        // ─────────────────────────────────────────────────────────────────────

        /// Strategy to generate random principal specifications.
        fn principal_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                // Unconstrained principal
                Just("principal".to_string()),
                // Specific billet principal
                billet_name_strategy().prop_map(|name| format!(
                    r#"principal == Quartermaster::Billet::"{}""#, name
                )),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_principal_is_unconstrained(
                action in action_strategy(),
                owning_billet in billet_name_strategy(),
                principal in principal_strategy(),
            ) {
                let resource = format!(r#"resource == Quartermaster::Billet::"{}""#, owning_billet);
                let statement = build_policy(&action, &principal, &resource);

                let result = PolicyCrudService::validate_resource_scope(&statement, &owning_billet);
                prop_assert!(
                    result.is_ok(),
                    "Expected Ok(()) regardless of principal. principal={}, action={}, billet={}, got {:?}",
                    principal, action, owning_billet, result
                );
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Property 5: Multi-statement rejection
        // Feature: principal-scope-validation, Property 5: Multi-statement rejection
        // Validates: Requirements 1.4
        // ─────────────────────────────────────────────────────────────────────
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_multi_statement_rejection(
                valid_action in action_strategy(),
                invalid_action in action_strategy(),
                owning_billet in billet_name_strategy(),
                other_billet in billet_name_strategy(),
                use_unconstrained in proptest::bool::ANY,
            ) {
                prop_assume!(owning_billet != other_billet);

                // Build a valid statement
                let valid_resource = format!(r#"resource == Quartermaster::Billet::"{}""#, owning_billet);
                let valid_stmt = build_policy(&valid_action, "principal", &valid_resource);

                // Build an invalid statement (either unconstrained or mismatched)
                let invalid_stmt = if use_unconstrained {
                    build_policy(&invalid_action, "principal", "resource")
                } else {
                    let bad_resource = format!(r#"resource == Quartermaster::Billet::"{}""#, other_billet);
                    build_policy(&invalid_action, "principal", &bad_resource)
                };

                // Combine into a multi-statement policy set
                let combined = format!("{}\n{}", valid_stmt, invalid_stmt);

                let result = PolicyCrudService::validate_resource_scope(&combined, &owning_billet);
                prop_assert!(
                    matches!(result, Err(PolicyCrudError::InvalidResourceScope(_))),
                    "Expected InvalidResourceScope for multi-statement with invalid entry. got {:?}",
                    result
                );
            }
        }
    }
}
