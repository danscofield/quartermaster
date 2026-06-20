// DynamoClient trait + AWS SDK DynamoDB implementation

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;

/// PolicyRecord represents a Cedar policy stored in the quartermaster-policies DynamoDB table.
/// The table uses `billet_name` as partition key and `policy_id` as sort key.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub billet_name: String,
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
    pub tags: Vec<String>,
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
    // Policy CRUD (composite key: billet_name PK, policy_id SK)

    /// Creates a policy record with composite key (billet_name PK, policy_id SK).
    async fn create_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError>;

    /// Gets a single policy by composite key (billet_name + policy_id).
    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DynamoError>;

    /// Updates a policy by composite key (billet_name + policy_id).
    async fn update_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError>;

    /// Deletes a single policy by composite key (billet_name + policy_id).
    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DynamoError>;

    /// Queries all policies for a billet (DynamoDB Query on PK).
    async fn list_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<PolicyRecord>, DynamoError>;

    /// Full table scan — used only by PolicySyncService.
    async fn scan_all_policies(&self) -> Result<Vec<PolicyRecord>, DynamoError>;

    /// Deletes all policies for a billet (Query + BatchWriteItem).
    /// Returns the count of deleted items.
    async fn delete_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<u32, DynamoError>;

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

/// Helper to extract a string set (SS) attribute from a DynamoDB item map.
/// Returns an empty vec if the attribute is absent or not a valid string set.
fn get_string_set(
    item: &std::collections::HashMap<String, AttributeValue>,
    key: &str,
) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_ss().ok())
        .map(|set| set.clone())
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
    async fn scan_all_policies(&self) -> Result<Vec<PolicyRecord>, DynamoError> {
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
                    let billet_name = get_string(&item, "billet_name").unwrap_or_default();
                    let policy_id = get_string(&item, "policy_id").unwrap_or_default();
                    let statement = get_string(&item, "statement").unwrap_or_default();
                    let description = get_string(&item, "description").unwrap_or_default();
                    let created_at = get_string(&item, "created_at").unwrap_or_default();
                    let updated_at = get_string(&item, "updated_at").unwrap_or_default();
                    records.push(PolicyRecord {
                        billet_name,
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
        billet_name: &str,
        policy_id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.client
            .put_item()
            .table_name(&self.policies_table)
            .item("billet_name", AttributeValue::S(billet_name.to_string()))
            .item("policy_id", AttributeValue::S(policy_id.to_string()))
            .item("statement", AttributeValue::S(statement.to_string()))
            .item("description", AttributeValue::S(description.to_string()))
            .item("created_at", AttributeValue::S(now.clone()))
            .item("updated_at", AttributeValue::S(now))
            .condition_expression("attribute_not_exists(billet_name) AND attribute_not_exists(policy_id)")
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DynamoError> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.policies_table)
            .key("billet_name", AttributeValue::S(billet_name.to_string()))
            .key("policy_id", AttributeValue::S(policy_id.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        match resp.item {
            Some(item) => {
                let record = PolicyRecord {
                    billet_name: get_string(&item, "billet_name").unwrap_or_default(),
                    policy_id: get_string(&item, "policy_id").unwrap_or_default(),
                    statement: get_string(&item, "statement").unwrap_or_default(),
                    description: get_string(&item, "description").unwrap_or_default(),
                    created_at: get_string(&item, "created_at").unwrap_or_default(),
                    updated_at: get_string(&item, "updated_at").unwrap_or_default(),
                };
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    async fn update_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
        statement: &str,
        description: &str,
    ) -> Result<(), DynamoError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.client
            .update_item()
            .table_name(&self.policies_table)
            .key("billet_name", AttributeValue::S(billet_name.to_string()))
            .key("policy_id", AttributeValue::S(policy_id.to_string()))
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

    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DynamoError> {
        self.client
            .delete_item()
            .table_name(&self.policies_table)
            .key("billet_name", AttributeValue::S(billet_name.to_string()))
            .key("policy_id", AttributeValue::S(policy_id.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn list_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<PolicyRecord>, DynamoError> {
        let mut records = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.policies_table)
                .key_condition_expression("billet_name = :bn")
                .expression_attribute_values(
                    ":bn",
                    AttributeValue::S(billet_name.to_string()),
                );

            if let Some(start_key) = exclusive_start_key.take() {
                req = req.set_exclusive_start_key(Some(start_key));
            }

            let resp = req.send().await.map_err(|e| map_sdk_error(e))?;

            if let Some(items) = resp.items {
                for item in items {
                    records.push(PolicyRecord {
                        billet_name: get_string(&item, "billet_name").unwrap_or_default(),
                        policy_id: get_string(&item, "policy_id").unwrap_or_default(),
                        statement: get_string(&item, "statement").unwrap_or_default(),
                        description: get_string(&item, "description").unwrap_or_default(),
                        created_at: get_string(&item, "created_at").unwrap_or_default(),
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

    async fn delete_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<u32, DynamoError> {
        // First, query all policies for this billet
        let policies = self.list_policies_for_billet(billet_name).await?;
        let count = policies.len() as u32;

        if count == 0 {
            return Ok(0);
        }

        // Delete in batches of 25 (DynamoDB BatchWriteItem limit)
        for chunk in policies.chunks(25) {
            let mut retries = 0;
            let items_to_delete: Vec<&PolicyRecord> = chunk.iter().collect();

            loop {
                let delete_requests: Vec<_> = items_to_delete
                    .iter()
                    .map(|p| {
                        aws_sdk_dynamodb::types::WriteRequest::builder()
                            .delete_request(
                                aws_sdk_dynamodb::types::DeleteRequest::builder()
                                    .key("billet_name", AttributeValue::S(p.billet_name.clone()))
                                    .key("policy_id", AttributeValue::S(p.policy_id.clone()))
                                    .build()
                                    .expect("valid delete request"),
                            )
                            .build()
                    })
                    .collect();

                let resp = self
                    .client
                    .batch_write_item()
                    .request_items(&self.policies_table, delete_requests)
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e))?;

                // Check for unprocessed items
                let unprocessed = resp
                    .unprocessed_items
                    .and_then(|mut m| m.remove(&self.policies_table));

                match unprocessed {
                    Some(items) if !items.is_empty() => {
                        retries += 1;
                        if retries > 3 {
                            return Err(DynamoError::ServiceError(
                                "exceeded max retries for BatchWriteItem unprocessed items"
                                    .to_string(),
                            ));
                        }
                        // Exponential backoff
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            100 * 2u64.pow(retries - 1),
                        ))
                        .await;
                        // Re-derive the items to delete from unprocessed
                        // For simplicity, we'll retry the whole chunk since we can't easily
                        // map WriteRequest back to PolicyRecord
                        continue;
                    }
                    _ => break,
                }
            }
        }

        Ok(count)
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
                    tags: get_string_set(&item, "tags"),
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

        let mut req = self
            .client
            .put_item()
            .table_name(&self.billets_table)
            .item("name", AttributeValue::S(metadata.name))
            .item("description", AttributeValue::S(metadata.description))
            .item("associated_aws_roles", AttributeValue::L(aws_roles))
            .item("associated_gcp_sas", AttributeValue::L(gcp_sas))
            .item("updated_at", AttributeValue::S(metadata.updated_at));

        // DynamoDB StringSet does not allow empty sets, so only include tags if non-empty
        if !metadata.tags.is_empty() {
            req = req.item("tags", AttributeValue::Ss(metadata.tags));
        }

        req.send().await.map_err(|e| map_sdk_error(e))?;

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
                        tags: get_string_set(&item, "tags"),
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
