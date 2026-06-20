// Policy CRUD service

use std::sync::Arc;

use cedar_policy::PolicySet;
use serde::{Deserialize, Serialize};

use crate::dynamo::{DynamoClient, DynamoError};

/// Errors that can occur during policy CRUD operations.
#[derive(Debug)]
pub enum PolicyCrudError {
    /// The Cedar statement is syntactically invalid (400).
    InvalidStatement(String),
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
    dynamo_client: Arc<dyn DynamoClient>,
}

impl PolicyCrudService {
    /// Creates a new PolicyCrudService.
    pub fn new(dynamo_client: Arc<dyn DynamoClient>) -> Self {
        Self { dynamo_client }
    }

    /// Validates that the given statement is a syntactically valid Cedar policy set.
    fn validate_cedar_statement(statement: &str) -> Result<(), PolicyCrudError> {
        statement
            .parse::<PolicySet>()
            .map_err(|e| PolicyCrudError::InvalidStatement(e.to_string()))?;
        Ok(())
    }

    /// Creates a new Cedar policy.
    ///
    /// 1. Validates Cedar statement syntax (parse with `PolicySet::from_str`)
    /// 2. Generates a UUID for the policy_id
    /// 3. Writes to quartermaster-policies DynamoDB table
    /// 4. Returns 201-equivalent response with id and metadata
    pub async fn create(
        &self,
        statement: &str,
        description: &str,
    ) -> Result<PolicyCreateResponse, PolicyCrudError> {
        // Validate Cedar statement syntax
        Self::validate_cedar_statement(statement)?;

        // Generate UUID for policy_id
        let policy_id = uuid::Uuid::new_v4().to_string();

        // Write to DynamoDB
        self.dynamo_client
            .create_policy(&policy_id, statement, description)
            .await
            .map_err(|e| PolicyCrudError::InternalError(e.to_string()))?;

        // Build created_at timestamp (matches what DynamoDB stores)
        let created_at = chrono::Utc::now().to_rfc3339();

        Ok(PolicyCreateResponse {
            policy_id,
            statement: statement.to_string(),
            description: description.to_string(),
            created_at,
        })
    }

    /// Updates an existing Cedar policy.
    ///
    /// 1. Validates Cedar statement syntax
    /// 2. Calls DynamoClient::update_policy
    /// 3. Maps DynamoError::NotFound → PolicyCrudError::NotFound
    pub async fn update(
        &self,
        id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), PolicyCrudError> {
        // Validate Cedar statement syntax
        Self::validate_cedar_statement(statement)?;

        // Update in DynamoDB
        self.dynamo_client
            .update_policy(id, statement, description)
            .await
            .map_err(|e| match e {
                DynamoError::NotFound(_) => PolicyCrudError::NotFound(id.to_string()),
                other => PolicyCrudError::InternalError(other.to_string()),
            })?;

        Ok(())
    }

    /// Deletes a Cedar policy.
    ///
    /// 1. Calls DynamoClient::delete_policy
    /// 2. Maps errors appropriately
    pub async fn delete(&self, id: &str) -> Result<(), PolicyCrudError> {
        self.dynamo_client
            .delete_policy(id)
            .await
            .map_err(|e| match e {
                DynamoError::NotFound(_) => PolicyCrudError::NotFound(id.to_string()),
                other => PolicyCrudError::InternalError(other.to_string()),
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamo::MockDynamoClient;

    /// A valid Cedar policy statement for testing.
    const VALID_STATEMENT: &str = r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#;

    /// An invalid Cedar policy statement for testing.
    const INVALID_STATEMENT: &str = r#"this is not valid cedar syntax{"#;

    #[tokio::test]
    async fn test_create_success() {
        let mut mock = MockDynamoClient::new();
        mock.expect_create_policy()
            .withf(|_id, stmt, desc| {
                stmt == VALID_STATEMENT && desc == "Allow payments"
            })
            .returning(|_, _, _| Ok(()));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.create(VALID_STATEMENT, "Allow payments").await;
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
        let mock = MockDynamoClient::new();
        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.create(INVALID_STATEMENT, "Bad policy").await;
        assert!(matches!(result, Err(PolicyCrudError::InvalidStatement(_))));
    }

    #[tokio::test]
    async fn test_create_dynamo_error() {
        let mut mock = MockDynamoClient::new();
        mock.expect_create_policy()
            .returning(|_, _, _| Err(DynamoError::ServiceError("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.create(VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_update_success() {
        let mut mock = MockDynamoClient::new();
        mock.expect_update_policy()
            .withf(|id, stmt, desc| {
                id == "policy-123" && stmt == VALID_STATEMENT && desc == "Updated"
            })
            .returning(|_, _, _| Ok(()));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.update("policy-123", VALID_STATEMENT, "Updated").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_invalid_statement() {
        let mock = MockDynamoClient::new();
        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.update("policy-123", INVALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InvalidStatement(_))));
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut mock = MockDynamoClient::new();
        mock.expect_update_policy()
            .returning(|_, _, _| Err(DynamoError::NotFound("not found".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.update("nonexistent", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_dynamo_service_error() {
        let mut mock = MockDynamoClient::new();
        mock.expect_update_policy()
            .returning(|_, _, _| Err(DynamoError::ServiceError("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.update("policy-123", VALID_STATEMENT, "desc").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_delete_success() {
        let mut mock = MockDynamoClient::new();
        mock.expect_delete_policy()
            .withf(|id| id == "policy-123")
            .returning(|_| Ok(()));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.delete("policy-123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut mock = MockDynamoClient::new();
        mock.expect_delete_policy()
            .returning(|_| Err(DynamoError::NotFound("not found".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.delete("nonexistent").await;
        assert!(matches!(result, Err(PolicyCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_dynamo_service_error() {
        let mut mock = MockDynamoClient::new();
        mock.expect_delete_policy()
            .returning(|_| Err(DynamoError::ServiceError("timeout".to_string())));

        let service = PolicyCrudService::new(Arc::new(mock));

        let result = service.delete("policy-123").await;
        assert!(matches!(result, Err(PolicyCrudError::InternalError(_))));
    }
}
