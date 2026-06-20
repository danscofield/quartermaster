use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;

use crate::config::backends::DynamoDbConfig;

use super::{BilletRecord, DataStore, DataStoreError, EphemeralKeyRecord, PolicyRecord};

/// Helper to extract a string attribute from a DynamoDB item map.
fn get_string(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).cloned()
}

/// Helper to extract a string list (L of S) attribute from a DynamoDB item map.
fn get_string_list(item: &HashMap<String, AttributeValue>, key: &str) -> Vec<String> {
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
fn get_string_set(item: &HashMap<String, AttributeValue>, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_ss().ok())
        .map(|set| set.clone())
        .unwrap_or_default()
}

/// Helper to extract a binary (B) attribute from a DynamoDB item map.
fn get_binary(item: &HashMap<String, AttributeValue>, key: &str) -> Vec<u8> {
    item.get(key)
        .and_then(|v| v.as_b().ok())
        .map(|blob| blob.as_ref().to_vec())
        .unwrap_or_default()
}

/// Maps an AWS SDK DynamoDB error to a `DataStoreError`.
fn map_sdk_error<E: std::fmt::Display>(err: E) -> DataStoreError {
    let msg = err.to_string();
    if msg.contains("ConditionalCheckFailed") || msg.contains("ConditionalCheckFailedException") {
        DataStoreError::Conflict(msg)
    } else if msg.contains("ResourceNotFoundException") || msg.contains("ResourceNotFound") {
        DataStoreError::NotFound(msg)
    } else {
        DataStoreError::Internal(msg)
    }
}

/// DynamoDB-backed implementation of the `DataStore` trait.
///
/// This is a thin adapter over the AWS DynamoDB SDK, maintaining the same
/// schema as the legacy `AwsDynamoClient`:
/// - Billets table: PK = `name`
/// - Policies table: PK = `billet_name`, SK = `policy_id`
/// - Keys table: PK = `purpose`, SK = `key_id`
pub struct DynamoDataStore {
    client: Client,
    billets_table: String,
    policies_table: String,
    keys_table: String,
}

impl DynamoDataStore {
    /// Creates a new `DynamoDataStore` from a `DynamoDbConfig` and AWS SDK config.
    pub fn new(config: &DynamoDbConfig, sdk_config: &aws_config::SdkConfig) -> Self {
        let client = Client::new(sdk_config);

        // Derive the keys table name from the billets table:
        // e.g. "quartermaster-billets" → "quartermaster-keys"
        let prefix = config
            .billets_table
            .trim_end_matches("-billets")
            .to_string();
        let keys_table = format!("{}-keys", prefix);

        Self {
            client,
            billets_table: config.billets_table.clone(),
            policies_table: config.policies_table.clone(),
            keys_table,
        }
    }

    /// Convert a DynamoDB item map to a `BilletRecord`.
    fn item_to_billet(item: &HashMap<String, AttributeValue>) -> BilletRecord {
        BilletRecord {
            name: get_string(item, "name").unwrap_or_default(),
            description: get_string(item, "description").unwrap_or_default(),
            associated_aws_roles: get_string_list(item, "associated_aws_roles"),
            associated_gcp_sas: get_string_list(item, "associated_gcp_sas"),
            tags: get_string_set(item, "tags"),
            created_at: get_string(item, "created_at").unwrap_or_default(),
            updated_at: get_string(item, "updated_at").unwrap_or_default(),
        }
    }

    /// Convert a DynamoDB item map to a `PolicyRecord`.
    fn item_to_policy(item: &HashMap<String, AttributeValue>) -> PolicyRecord {
        PolicyRecord {
            billet_name: get_string(item, "billet_name").unwrap_or_default(),
            policy_id: get_string(item, "policy_id").unwrap_or_default(),
            statement: get_string(item, "statement").unwrap_or_default(),
            description: get_string(item, "description").unwrap_or_default(),
            created_at: get_string(item, "created_at").unwrap_or_default(),
            updated_at: get_string(item, "updated_at").unwrap_or_default(),
        }
    }

    /// Convert a DynamoDB item map to an `EphemeralKeyRecord`.
    fn item_to_key(item: &HashMap<String, AttributeValue>) -> EphemeralKeyRecord {
        EphemeralKeyRecord {
            key_id: get_string(item, "key_id").unwrap_or_default(),
            public_key_pem: get_string(item, "public_key_pem").unwrap_or_default(),
            private_key_encrypted: get_binary(item, "private_key_encrypted"),
            kms_attestation: get_binary(item, "kms_attestation"),
            algorithm: get_string(item, "algorithm").unwrap_or_default(),
            created_at: get_string(item, "created_at").unwrap_or_default(),
            expires_at: get_string(item, "expires_at").unwrap_or_default(),
            purpose: get_string(item, "purpose").unwrap_or_default(),
        }
    }
}

#[async_trait]
impl DataStore for DynamoDataStore {
    // ── Billet Operations ──

    async fn create_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        let aws_roles: Vec<AttributeValue> = record
            .associated_aws_roles
            .iter()
            .map(|r| AttributeValue::S(r.clone()))
            .collect();
        let gcp_sas: Vec<AttributeValue> = record
            .associated_gcp_sas
            .iter()
            .map(|s| AttributeValue::S(s.clone()))
            .collect();

        let mut req = self
            .client
            .put_item()
            .table_name(&self.billets_table)
            .item("name", AttributeValue::S(record.name.clone()))
            .item("description", AttributeValue::S(record.description.clone()))
            .item("associated_aws_roles", AttributeValue::L(aws_roles))
            .item("associated_gcp_sas", AttributeValue::L(gcp_sas))
            .item("created_at", AttributeValue::S(record.created_at.clone()))
            .item("updated_at", AttributeValue::S(record.updated_at.clone()))
            .condition_expression("attribute_not_exists(#n)")
            .expression_attribute_names("#n", "name");

        // DynamoDB StringSet does not allow empty sets
        if !record.tags.is_empty() {
            req = req.item("tags", AttributeValue::Ss(record.tags.clone()));
        }

        req.send().await.map_err(|e| map_sdk_error(e))?;
        Ok(())
    }

    async fn get_billet(&self, name: &str) -> Result<Option<BilletRecord>, DataStoreError> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.billets_table)
            .key("name", AttributeValue::S(name.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(resp.item.map(|item| Self::item_to_billet(&item)))
    }

    async fn update_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        let aws_roles: Vec<AttributeValue> = record
            .associated_aws_roles
            .iter()
            .map(|r| AttributeValue::S(r.clone()))
            .collect();
        let gcp_sas: Vec<AttributeValue> = record
            .associated_gcp_sas
            .iter()
            .map(|s| AttributeValue::S(s.clone()))
            .collect();

        let mut req = self
            .client
            .update_item()
            .table_name(&self.billets_table)
            .key("name", AttributeValue::S(record.name.clone()))
            .update_expression(
                "SET description = :desc, associated_aws_roles = :roles, associated_gcp_sas = :sas, updated_at = :ts, created_at = if_not_exists(created_at, :cat)",
            )
            .expression_attribute_values(":desc", AttributeValue::S(record.description.clone()))
            .expression_attribute_values(":roles", AttributeValue::L(aws_roles))
            .expression_attribute_values(":sas", AttributeValue::L(gcp_sas))
            .expression_attribute_values(":ts", AttributeValue::S(record.updated_at.clone()))
            .expression_attribute_values(":cat", AttributeValue::S(record.created_at.clone()))
            .condition_expression("attribute_exists(#n)")
            .expression_attribute_names("#n", "name");

        // Handle tags: DynamoDB SS does not allow empty sets
        if !record.tags.is_empty() {
            req = req
                .update_expression(
                    "SET description = :desc, associated_aws_roles = :roles, associated_gcp_sas = :sas, updated_at = :ts, created_at = if_not_exists(created_at, :cat), tags = :tags",
                )
                .expression_attribute_values(":tags", AttributeValue::Ss(record.tags.clone()));
        }

        req.send().await.map_err(|e| map_sdk_error(e))?;
        Ok(())
    }

    async fn delete_billet_cascade(&self, name: &str) -> Result<u32, DataStoreError> {
        // First query all policies for this billet
        let policies = self.list_policies_for_billet(name).await?;
        let policy_count = policies.len() as u32;

        // Delete policies in batches of 25 (DynamoDB BatchWriteItem limit)
        for chunk in policies.chunks(25) {
            let mut retries = 0u32;

            loop {
                let delete_requests: Vec<_> = chunk
                    .iter()
                    .map(|p| {
                        aws_sdk_dynamodb::types::WriteRequest::builder()
                            .delete_request(
                                aws_sdk_dynamodb::types::DeleteRequest::builder()
                                    .key(
                                        "billet_name",
                                        AttributeValue::S(p.billet_name.clone()),
                                    )
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
                            return Err(DataStoreError::Internal(
                                "exceeded max retries for BatchWriteItem unprocessed items"
                                    .to_string(),
                            ));
                        }
                        // Exponential backoff
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            100 * 2u64.pow(retries - 1),
                        ))
                        .await;
                        continue;
                    }
                    _ => break,
                }
            }
        }

        // Delete the billet itself
        self.client
            .delete_item()
            .table_name(&self.billets_table)
            .key("name", AttributeValue::S(name.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        // Return count: policies + the billet itself
        Ok(policy_count + 1)
    }

    async fn list_billets(&self) -> Result<Vec<BilletRecord>, DataStoreError> {
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
                    records.push(Self::item_to_billet(&item));
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

    // ── Policy Operations ──

    async fn create_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        self.client
            .put_item()
            .table_name(&self.policies_table)
            .item(
                "billet_name",
                AttributeValue::S(record.billet_name.clone()),
            )
            .item("policy_id", AttributeValue::S(record.policy_id.clone()))
            .item("statement", AttributeValue::S(record.statement.clone()))
            .item("description", AttributeValue::S(record.description.clone()))
            .item("created_at", AttributeValue::S(record.created_at.clone()))
            .item("updated_at", AttributeValue::S(record.updated_at.clone()))
            .condition_expression(
                "attribute_not_exists(billet_name) AND attribute_not_exists(policy_id)",
            )
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DataStoreError> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.policies_table)
            .key("billet_name", AttributeValue::S(billet_name.to_string()))
            .key("policy_id", AttributeValue::S(policy_id.to_string()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(resp.item.map(|item| Self::item_to_policy(&item)))
    }

    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        self.client
            .update_item()
            .table_name(&self.policies_table)
            .key(
                "billet_name",
                AttributeValue::S(record.billet_name.clone()),
            )
            .key("policy_id", AttributeValue::S(record.policy_id.clone()))
            .update_expression(
                "SET statement = :stmt, description = :desc, updated_at = :ts",
            )
            .expression_attribute_values(":stmt", AttributeValue::S(record.statement.clone()))
            .expression_attribute_values(":desc", AttributeValue::S(record.description.clone()))
            .expression_attribute_values(":ts", AttributeValue::S(record.updated_at.clone()))
            .condition_expression("attribute_exists(billet_name)")
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DataStoreError> {
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
    ) -> Result<Vec<PolicyRecord>, DataStoreError> {
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
                    records.push(Self::item_to_policy(&item));
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

    async fn list_all_policies(&self) -> Result<Vec<PolicyRecord>, DataStoreError> {
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
                    records.push(Self::item_to_policy(&item));
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

    // ── Ephemeral Key Operations ──

    async fn put_ephemeral_key(&self, record: &EphemeralKeyRecord) -> Result<(), DataStoreError> {
        self.client
            .put_item()
            .table_name(&self.keys_table)
            .item("purpose", AttributeValue::S(record.purpose.clone()))
            .item("key_id", AttributeValue::S(record.key_id.clone()))
            .item(
                "public_key_pem",
                AttributeValue::S(record.public_key_pem.clone()),
            )
            .item(
                "private_key_encrypted",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    record.private_key_encrypted.clone(),
                )),
            )
            .item(
                "kms_attestation",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    record.kms_attestation.clone(),
                )),
            )
            .item("algorithm", AttributeValue::S(record.algorithm.clone()))
            .item("created_at", AttributeValue::S(record.created_at.clone()))
            .item("expires_at", AttributeValue::S(record.expires_at.clone()))
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }

    async fn get_active_ephemeral_keys(
        &self,
        purpose: &str,
    ) -> Result<Vec<EphemeralKeyRecord>, DataStoreError> {
        let now = chrono::Utc::now().to_rfc3339();

        let mut records = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.keys_table)
                .key_condition_expression("purpose = :p")
                .filter_expression("expires_at > :now")
                .expression_attribute_values(":p", AttributeValue::S(purpose.to_string()))
                .expression_attribute_values(":now", AttributeValue::S(now.clone()));

            if let Some(start_key) = exclusive_start_key.take() {
                req = req.set_exclusive_start_key(Some(start_key));
            }

            let resp = req.send().await.map_err(|e| map_sdk_error(e))?;

            if let Some(items) = resp.items {
                for item in items {
                    records.push(Self::item_to_key(&item));
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

    async fn delete_expired_ephemeral_keys(
        &self,
        purpose: &str,
        before: &str,
    ) -> Result<u32, DataStoreError> {
        // Query all keys for this purpose that have expired
        let mut expired_keys = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.keys_table)
                .key_condition_expression("purpose = :p")
                .filter_expression("expires_at <= :before")
                .expression_attribute_values(":p", AttributeValue::S(purpose.to_string()))
                .expression_attribute_values(":before", AttributeValue::S(before.to_string()));

            if let Some(start_key) = exclusive_start_key.take() {
                req = req.set_exclusive_start_key(Some(start_key));
            }

            let resp = req.send().await.map_err(|e| map_sdk_error(e))?;

            if let Some(items) = resp.items {
                for item in items {
                    if let Some(key_id) = get_string(&item, "key_id") {
                        expired_keys.push(key_id);
                    }
                }
            }

            match resp.last_evaluated_key {
                Some(key) if !key.is_empty() => {
                    exclusive_start_key = Some(key);
                }
                _ => break,
            }
        }

        let count = expired_keys.len() as u32;

        // Delete expired keys in batches of 25
        for chunk in expired_keys.chunks(25) {
            let delete_requests: Vec<_> = chunk
                .iter()
                .map(|key_id| {
                    aws_sdk_dynamodb::types::WriteRequest::builder()
                        .delete_request(
                            aws_sdk_dynamodb::types::DeleteRequest::builder()
                                .key("purpose", AttributeValue::S(purpose.to_string()))
                                .key("key_id", AttributeValue::S(key_id.clone()))
                                .build()
                                .expect("valid delete request"),
                        )
                        .build()
                })
                .collect();

            self.client
                .batch_write_item()
                .request_items(&self.keys_table, delete_requests)
                .send()
                .await
                .map_err(|e| map_sdk_error(e))?;
        }

        Ok(count)
    }

    // ── Health ──

    async fn ping(&self) -> Result<(), DataStoreError> {
        self.client
            .describe_table()
            .table_name(&self.billets_table)
            .send()
            .await
            .map_err(|e| map_sdk_error(e))?;

        Ok(())
    }
}
