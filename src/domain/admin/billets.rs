// Billet CRUD service

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::datastore::{DataStore, BilletRecord};

use super::tags::validate_tags;

/// Errors that can occur during billet CRUD operations.
#[derive(Debug)]
pub enum BilletCrudError {
    /// The billet name is empty (400).
    NameEmpty,
    /// One or more tags are invalid (400).
    InvalidTags(String),
    /// A billet with this name already exists (409).
    AlreadyExists(String),
    /// The billet was not found (404).
    NotFound(String),
    /// The billet is protected and cannot be deleted (403).
    ProtectedBillet(String),
    /// An internal error occurred (500).
    InternalError(String),
}

impl std::fmt::Display for BilletCrudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BilletCrudError::NameEmpty => write!(f, "billet name must not be empty"),
            BilletCrudError::InvalidTags(msg) => write!(f, "{}", msg),
            BilletCrudError::AlreadyExists(name) => {
                write!(f, "billet '{}' already exists", name)
            }
            BilletCrudError::NotFound(name) => write!(f, "billet '{}' not found", name),
            BilletCrudError::ProtectedBillet(name) => {
                write!(f, "billet '{}' is protected and cannot be deleted", name)
            }
            BilletCrudError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for BilletCrudError {}

/// Response for GET /admin/billets/{name} — includes policies.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct BilletWithPolicies {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub tags: Vec<String>,
    pub updated_at: String,
    pub policies: Vec<PolicySummary>,
}

/// Summary of a policy attached to a billet.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct PolicySummary {
    pub id: String,
    pub statement: String,
    pub description: String,
}

/// Represents a billet in the list response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BilletListItem {
    pub name: String,
    pub description: String,
}

/// BilletCrudService provides billet management logic for the admin control plane.
pub struct BilletCrudService {
    data_store: Arc<dyn DataStore>,
}

impl BilletCrudService {
    /// Creates a new BilletCrudService.
    pub fn new(
        data_store: Arc<dyn DataStore>,
    ) -> Self {
        Self {
            data_store,
        }
    }

    /// Creates a new billet metadata record.
    ///
    /// Validates that the name is non-empty, tags are valid, and the name is unique,
    /// then writes to DynamoDB.
    pub async fn create(
        &self,
        name: &str,
        description: &str,
        aws_roles: Vec<String>,
        gcp_sas: Vec<String>,
        tags: Vec<String>,
    ) -> Result<BilletRecord, BilletCrudError> {
        // Validate name is non-empty
        if name.trim().is_empty() {
            return Err(BilletCrudError::NameEmpty);
        }

        // Validate tags before persistence
        validate_tags(&tags).map_err(BilletCrudError::InvalidTags)?;

        // Check uniqueness — if a billet with this name already exists, return conflict
        let existing = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        if existing.is_some() {
            return Err(BilletCrudError::AlreadyExists(name.to_string()));
        }

        let now = chrono::Utc::now().to_rfc3339();
        let record = BilletRecord {
            name: name.to_string(),
            description: description.to_string(),
            associated_aws_roles: aws_roles.clone(),
            associated_gcp_sas: gcp_sas.clone(),
            tags: tags.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        self.data_store
            .create_billet(&record)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        Ok(record)
    }

    /// Lists all billets from the data store (single source of truth).
    pub async fn list(&self) -> Result<Vec<BilletListItem>, BilletCrudError> {
        let db_billets = self
            .data_store
            .list_billets()
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        let mut items: Vec<BilletListItem> = db_billets
            .into_iter()
            .map(|b| BilletListItem {
                name: b.name,
                description: b.description,
            })
            .collect();

        // Sort by name for consistent ordering
        items.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(items)
    }

    /// Retrieves a single billet metadata record by name.
    pub async fn get(&self, name: &str) -> Result<BilletRecord, BilletCrudError> {
        let record = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        match record {
            Some(r) => Ok(r),
            None => Err(BilletCrudError::NotFound(name.to_string())),
        }
    }

    /// Gets a billet with its attached policies.
    ///
    /// Fetches billet metadata and all policies for the billet, returning them
    /// combined in a single response struct. Returns 404 if the billet does not exist.
    pub async fn get_with_policies(
        &self,
        name: &str,
    ) -> Result<BilletWithPolicies, BilletCrudError> {
        // Fetch billet metadata — return NotFound if it doesn't exist
        let record = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?
            .ok_or_else(|| BilletCrudError::NotFound(name.to_string()))?;

        // Fetch all policies for this billet
        let policy_records = self
            .data_store
            .list_policies_for_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        // Map PolicyRecord items to PolicySummary
        let policies: Vec<PolicySummary> = policy_records
            .into_iter()
            .map(|r| PolicySummary {
                id: r.policy_id,
                statement: r.statement,
                description: r.description,
            })
            .collect();

        Ok(BilletWithPolicies {
            name: record.name,
            description: record.description,
            associated_aws_roles: record.associated_aws_roles,
            associated_gcp_sas: record.associated_gcp_sas,
            tags: record.tags,
            updated_at: record.updated_at,
            policies,
        })
    }

    /// Updates a billet's metadata fields. Only fields present in the update are changed.
    ///
    /// Returns 404 if the billet does not exist.
    pub async fn update(
        &self,
        name: &str,
        description: Option<&str>,
        aws_roles: Option<Vec<String>>,
        gcp_sas: Option<Vec<String>>,
        tags: Option<Vec<String>>,
    ) -> Result<BilletRecord, BilletCrudError> {
        // Validate tags if present
        if let Some(ref new_tags) = tags {
            validate_tags(new_tags).map_err(BilletCrudError::InvalidTags)?;
        }

        // Fetch existing metadata
        let existing = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        let mut record = match existing {
            Some(r) => r,
            None => return Err(BilletCrudError::NotFound(name.to_string())),
        };

        // Merge provided fields — only override fields that are Some
        if let Some(desc) = description {
            record.description = desc.to_string();
        }
        if let Some(roles) = aws_roles {
            record.associated_aws_roles = roles;
        }
        if let Some(sas) = gcp_sas {
            record.associated_gcp_sas = sas;
        }
        if let Some(new_tags) = tags {
            record.tags = new_tags;
        }

        // Update timestamp
        record.updated_at = chrono::Utc::now().to_rfc3339();

        // Write back
        self.data_store
            .update_billet(&record)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        Ok(record)
    }

    /// Deletes a billet metadata record by name.
    ///
    /// Returns an error if the billet is a protected system billet
    /// (`quartermaster-admin` or `quartermaster-guardrails`).
    pub async fn delete(&self, name: &str) -> Result<(), BilletCrudError> {
        // Check if this is a protected system billet
        if name == "quartermaster-admin" || name == "quartermaster-guardrails" {
            return Err(BilletCrudError::ProtectedBillet(name.to_string()));
        }

        // Check if the billet exists before attempting deletion
        let existing = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        if existing.is_none() {
            return Err(BilletCrudError::NotFound(name.to_string()));
        }

        self.data_store
            .delete_billet_cascade(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Deletes a billet and all its attached policies (cascade).
    ///
    /// This performs a cascade delete: first removes all policies attached to the billet,
    /// then removes the billet metadata record itself.
    /// Returns an error if the billet is a protected system billet
    /// (`quartermaster-admin` or `quartermaster-guardrails`) or if the billet does not exist.
    pub async fn delete_cascade(&self, name: &str) -> Result<(), BilletCrudError> {
        // Check if this is a protected system billet
        if name == "quartermaster-admin" || name == "quartermaster-guardrails" {
            return Err(BilletCrudError::ProtectedBillet(name.to_string()));
        }

        // Check if the billet exists before attempting deletion
        let existing = self
            .data_store
            .get_billet(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        if existing.is_none() {
            return Err(BilletCrudError::NotFound(name.to_string()));
        }

        // Cascade delete (removes billet + all policies)
        self.data_store
            .delete_billet_cascade(name)
            .await
            .map_err(|e| BilletCrudError::InternalError(e.to_string()))?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::{MockDataStore, PolicyRecord, DataStoreError};

    fn sample_billet_record(name: &str) -> BilletRecord {
        BilletRecord {
            name: name.to_string(),
            description: format!("{} billet", name),
            associated_aws_roles: vec![],
            associated_gcp_sas: vec![],
            tags: vec![],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn test_create_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(None));
        mock.expect_create_billet().returning(|_| Ok(()));

        let service = BilletCrudService::new(Arc::new(mock));

        let result = service
            .create("payments", "Payments billet", vec!["arn:aws:iam::123:role/payments".to_string()], vec![], vec![])
            .await;

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.name, "payments");
        assert_eq!(metadata.description, "Payments billet");
        assert_eq!(metadata.associated_aws_roles, vec!["arn:aws:iam::123:role/payments"]);
        assert!(metadata.associated_gcp_sas.is_empty());
    }

    #[tokio::test]
    async fn test_create_empty_name() {
        let mock = MockDataStore::new();
        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.create("", "desc", vec![], vec![], vec![]).await;
        assert!(matches!(result, Err(BilletCrudError::NameEmpty)));
    }

    #[tokio::test]
    async fn test_create_whitespace_only_name() {
        let mock = MockDataStore::new();
        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.create("   ", "desc", vec![], vec![], vec![]).await;
        assert!(matches!(result, Err(BilletCrudError::NameEmpty)));
    }

    #[tokio::test]
    async fn test_create_already_exists() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(Some(sample_billet_record("payments"))));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.create("payments", "desc", vec![], vec![], vec![]).await;
        assert!(matches!(result, Err(BilletCrudError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_get_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "payments".to_string(),
                    description: "Payments billet".to_string(),
                    associated_aws_roles: vec!["arn:aws:iam::123:role/payments".to_string()],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.get("payments").await;
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.name, "payments");
        assert_eq!(metadata.description, "Payments billet");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "nonexistent")
            .returning(|_| Ok(None));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.get("nonexistent").await;
        assert!(matches!(result, Err(BilletCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(Some(sample_billet_record("payments"))));
        mock.expect_delete_billet_cascade()
            .withf(|name| name == "payments")
            .returning(|_| Ok(0));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete("payments").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_protected_billet() {
        let mock = MockDataStore::new();
        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete("quartermaster-admin").await;
        assert!(matches!(result, Err(BilletCrudError::ProtectedBillet(_))));
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "nonexistent")
            .returning(|_| Ok(None));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete("nonexistent").await;
        assert!(matches!(result, Err(BilletCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_returns_billets() {
        let mut mock = MockDataStore::new();
        mock.expect_list_billets().returning(|| {
            Ok(vec![
                sample_billet_record("analytics"),
                sample_billet_record("payments"),
            ])
        });

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.list().await;
        assert!(result.is_ok());
        let items = result.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "analytics");
        assert_eq!(items[1].name, "payments");
    }

    #[tokio::test]
    async fn test_create_datastore_error() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .returning(|_| Err(DataStoreError::Internal("connection refused".to_string())));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.create("payments", "desc", vec![], vec![], vec![]).await;
        assert!(matches!(result, Err(BilletCrudError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_update_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(Some(sample_billet_record("payments"))));
        mock.expect_update_billet().returning(|_| Ok(()));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.update("payments", Some("New description"), None, None, None).await;
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.description, "New description");
        assert_ne!(metadata.updated_at, "2024-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "nonexistent")
            .returning(|_| Ok(None));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.update("nonexistent", Some("desc"), None, None, None).await;
        assert!(matches!(result, Err(BilletCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_get_with_policies_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "payments".to_string(),
                    description: "Payments billet".to_string(),
                    associated_aws_roles: vec!["arn:aws:iam::123:role/payments".to_string()],
                    associated_gcp_sas: vec!["pay@gcp.iam".to_string()],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });
        mock.expect_list_policies_for_billet()
            .withf(|name| name == "payments")
            .returning(|_| {
                Ok(vec![
                    PolicyRecord {
                        billet_name: "payments".to_string(),
                        policy_id: "policy-1".to_string(),
                        statement: "permit(principal, action, resource);".to_string(),
                        description: "Allow all".to_string(),
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    },
                    PolicyRecord {
                        billet_name: "payments".to_string(),
                        policy_id: "policy-2".to_string(),
                        statement: "forbid(principal, action, resource);".to_string(),
                        description: "Deny all".to_string(),
                        created_at: "2024-01-02T00:00:00Z".to_string(),
                        updated_at: "2024-01-02T00:00:00Z".to_string(),
                    },
                ])
            });

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.get_with_policies("payments").await;
        assert!(result.is_ok());
        let billet = result.unwrap();
        assert_eq!(billet.name, "payments");
        assert_eq!(billet.policies.len(), 2);
        assert_eq!(billet.policies[0].id, "policy-1");
        assert_eq!(billet.policies[1].id, "policy-2");
    }

    #[tokio::test]
    async fn test_delete_cascade_success() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "payments")
            .returning(|_| Ok(Some(sample_billet_record("payments"))));
        mock.expect_delete_billet_cascade()
            .withf(|name| name == "payments")
            .returning(|_| Ok(3));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete_cascade("payments").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_cascade_protected_billet() {
        let mock = MockDataStore::new();
        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete_cascade("quartermaster-admin").await;
        assert!(matches!(result, Err(BilletCrudError::ProtectedBillet(_))));
    }

    #[tokio::test]
    async fn test_delete_cascade_not_found() {
        let mut mock = MockDataStore::new();
        mock.expect_get_billet()
            .withf(|name| name == "nonexistent")
            .returning(|_| Ok(None));

        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete_cascade("nonexistent").await;
        assert!(matches!(result, Err(BilletCrudError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_protected_guardrails_billet() {
        let mock = MockDataStore::new();
        let service = BilletCrudService::new(Arc::new(mock));
        let result = service.delete("quartermaster-guardrails").await;
        assert!(matches!(result, Err(BilletCrudError::ProtectedBillet(_))));
    }
}
