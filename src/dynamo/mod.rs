// DynamoClient trait + AWS SDK DynamoDB implementation

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;

/// PolicyRecord represents a Cedar policy stored in the quartermaster-policies DynamoDB table.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub statement: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

/// BilletMetadata represents billet metadata stored in the quartermaster-billets DynamoDB table.
/// Note: Billet names for authorization are derived from the PolicySet, not from this table.
/// This table stores descriptive metadata only.
#[derive(Debug, Clone)]
pub struct BilletMetadata {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub updated_at: String,
}

/// DynamoError represents errors from DynamoDB operations.
#[derive(Debug)]
pub enum DynamoError {
    /// The requested item was not found.
    NotFound(String),
    /// A conflict occurred (e.g., duplicate key).
    Conflict(String),
    /// A connectivity or SDK error.
    ServiceError(String),
}

impl std::fmt::Display for DynamoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DynamoError::NotFound(msg) => write!(f, "not found: {msg}"),
            DynamoError::Conflict(msg) => write!(f, "conflict: {msg}"),
            DynamoError::ServiceError(msg) => write!(f, "service error: {msg}"),
        }
    }
}

impl std::error::Error for DynamoError {}

/// DynamoClient provides access to the DynamoDB tables used by Quartermaster.
/// All external dependencies are accessed through this trait to enable test doubles.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DynamoClient: Send + Sync {
    // Policy CRUD

    /// Lists all policy records from the quartermaster-policies DynamoDB table.
    async fn list_policies(&self) -> Result<Vec<PolicyRecord>, DynamoError>;

    /// Creates a policy record in the quartermaster-policies DynamoDB table.
    async fn create_policy(
        &self,
        id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError>;

    /// Updates an existing policy record.
    async fn update_policy(
        &self,
        id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError>;

    /// Deletes a policy record from the quartermaster-policies DynamoDB table.
    async fn delete_policy(&self, id: &str) -> Result<(), DynamoError>;

    // Billet metadata CRUD

    /// Retrieves a specific billet metadata record by name.
    async fn get_billet_metadata(&self, name: &str) -> Result<Option<BilletMetadata>, DynamoError>;

    /// Creates or updates a billet metadata record in the quartermaster-billets DynamoDB table.
    async fn put_billet_metadata(&self, metadata: BilletMetadata) -> Result<(), DynamoError>;

    /// Removes a billet metadata record from the quartermaster-billets DynamoDB table.
    async fn delete_billet_metadata(&self, name: &str) -> Result<(), DynamoError>;

    /// Lists all billet metadata records from the quartermaster-billets DynamoDB table.
    async fn list_billet_metadata(&self) -> Result<Vec<BilletMetadata>, DynamoError>;

    // Health

    /// Checks connectivity to DynamoDB.
    async fn ping(&self) -> Result<(), DynamoError>;
}

// --- AWS SDK DynamoDB Implementation ---

/// AwsDynamoClient implements the DynamoClient trait using the AWS SDK for Rust.
pub struct AwsDynamoClient {
    client: Client,
    policies_table: String,
    billets_table: String,
}

impl AwsDynamoClient {
    /// Creates a new AwsDynamoClient from an AWS SDK config and table names.
    pub fn new(
        config: &aws_config::SdkConfig,
        policies_table: String,
        billets_table: String,
    ) -> Self {
        let client = Client::new(config);
        Self {
            client,
            policies_table,
            billets_table,
        }
    }
}

/// Helper to extract a string attribute from a DynamoDB item map.
fn get_string(
    item: &std::collections::HashMap<String, AttributeValue>,
    key: &str,
) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).cloned()
}

/// Helper to extract a string list attribute from a DynamoDB item map.
fn get_string_list(
    item: &std::collections::HashMap<String, AttributeValue>,
    key: &str,
) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_l().ok())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_s().ok().cloned())
                .collect()
        })
        .unwrap_or_default()
}

/// Maps an AWS SDK DynamoDB error to a DynamoError.
fn map_sdk_error<E: std::fmt::Display>(err: E) -> DynamoError {
    let msg = err.to_string();
    if msg.contains("ConditionalCheckFailed") || msg.contains("ConditionalCheckFailedException") {
        DynamoError::Conflict(msg)
    } else if msg.contains("ResourceNotFoundException") || msg.contains("ResourceNotFound") {
        DynamoError::NotFound(msg)
    } else {
        DynamoError::ServiceError(msg)
    }
}

#[async_trait]
impl DynamoClient for AwsDynamoClient {
    async fn list_policies(&self) -> Result<Vec<PolicyRecord>, DynamoError> {
        let mut records = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut req = self.client.scan().table_name(&self.policies_table);
            if let Some(start_key) = exclusive_start_key.take() {
                req = req.set_exclusive_start_key(Some(start_key));
            }

            let resp = req.send().await.map_err(|e| map_sdk_error(e))?;

            if let Some(items) = resp.items {
                for item in items {
                    let policy_id = get_string(&item, "policy_id").unwrap_or_default();
                    let statement = get_string(&item, "statement").unwrap_or_default();
                    let description = get_string(&item, "description").unwrap_or_default();
                    let created_at = get_string(&item, "created_at").unwrap_or_default();
                    let updated_at = get_string(&item, "updated_at").unwrap_or_default();
                    records.push(PolicyRecord {
                        policy_id,
                        statement,
                        description,
                        created_at,
                        updated_at,
                    });
                }
            }

            match resp.last_evaluated_key {
                Some(key) if !key.is_empty() => {
                    exclusive_start_key = Some(key);
                }
                _ => break,
            }
        }

        Ok(records)
    }

    async fn create_policy(
        &self,
        id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.client
            .put_item()
            .table_name(&self.policies_table)
            .item("policy_id", AttributeValue::S(id.to_string()))
            .item("statement", AttributeValue::S(statement.to_string()))
            .item("description", AttributeValue::S(description.to_string()))
            .item("created_at", AttributeValue::S(now.clone()))
            .item("updated_at", AttributeValue::S(now))
            .condition_expression("attribute_not_exists(policy_id)")
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn update_policy(
        &self,
        id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.client
            .update_item()
            .table_name(&self.policies_table)
            .key("policy_id", AttributeValue::S(id.to_string()))
            .update_expression(
                "SET statement = :stmt, description = :desc, updated_at = :ts",
            )
            .expression_attribute_values(":stmt", AttributeValue::S(statement.to_string()))
            .expression_attribute_values(":desc", AttributeValue::S(description.to_string()))
            .expression_attribute_values(":ts", AttributeValue::S(now))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn delete_policy(&self, id: &str) -> Result<(), DynamoError> {
        self.client
            .delete_item()
            .table_name(&self.policies_table)
            .key("policy_id", AttributeValue::S(id.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn get_billet_metadata(&self, name: &str) -> Result<Option<BilletMetadata>, DynamoError> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.billets_table)
            .key("name", AttributeValue::S(name.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        match resp.item {
            Some(item) => {
                let metadata = BilletMetadata {
                    name: get_string(&item, "name").unwrap_or_default(),
                    description: get_string(&item, "description").unwrap_or_default(),
                    associated_aws_roles: get_string_list(&item, "associated_aws_roles"),
                    associated_gcp_sas: get_string_list(&item, "associated_gcp_sas"),
                    updated_at: get_string(&item, "updated_at").unwrap_or_default(),
                };
                Ok(Some(metadata))
            }
            None => Ok(None),
        }
    }

    async fn put_billet_metadata(&self, metadata: BilletMetadata) -> Result<(), DynamoError> {
        let aws_roles: Vec<AttributeValue> = metadata
            .associated_aws_roles
            .iter()
            .map(|r| AttributeValue::S(r.clone()))
            .collect();
        let gcp_sas: Vec<AttributeValue> = metadata
            .associated_gcp_sas
            .iter()
            .map(|s| AttributeValue::S(s.clone()))
            .collect();

        self.client
            .put_item()
            .table_name(&self.billets_table)
            .item("name", AttributeValue::S(metadata.name))
            .item("description", AttributeValue::S(metadata.description))
            .item("associated_aws_roles", AttributeValue::L(aws_roles))
            .item("associated_gcp_sas", AttributeValue::L(gcp_sas))
            .item("updated_at", AttributeValue::S(metadata.updated_at))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn delete_billet_metadata(&self, name: &str) -> Result<(), DynamoError> {
        self.client
            .delete_item()
            .table_name(&self.billets_table)
            .key("name", AttributeValue::S(name.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn list_billet_metadata(&self) -> Result<Vec<BilletMetadata>, DynamoError> {
        let mut records = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut req = self.client.scan().table_name(&self.billets_table);
            if let Some(start_key) = exclusive_start_key.take() {
                req = req.set_exclusive_start_key(Some(start_key));
            }

            let resp = req.send().await.map_err(|e| map_sdk_error(e))?;

            if let Some(items) = resp.items {
                for item in items {
                    records.push(BilletMetadata {
                        name: get_string(&item, "name").unwrap_or_default(),
                        description: get_string(&item, "description").unwrap_or_default(),
                        associated_aws_roles: get_string_list(&item, "associated_aws_roles"),
                        associated_gcp_sas: get_string_list(&item, "associated_gcp_sas"),
                        updated_at: get_string(&item, "updated_at").unwrap_or_default(),
                    });
                }
            }

            match resp.last_evaluated_key {
                Some(key) if !key.is_empty() => {
                    exclusive_start_key = Some(key);
                }
                _ => break,
            }
        }

        Ok(records)
    }

    async fn ping(&self) -> Result<(), DynamoError> {
        self.client
            .describe_table()
            .table_name(&self.policies_table)
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }
}
