//! Google Cloud Firestore implementation of the `DataStore` trait.
//!
//! This module is gated behind the `gcp` feature flag.
//!
//! Storage layout:
//! - `{prefix}-billets` collection: documents keyed by billet name
//! - `{prefix}-policies` collection: flat documents keyed by `{billet_name}__{policy_id}`
//! - `{prefix}-keys` collection: ephemeral key documents keyed by `{purpose}__{key_id}`

use async_trait::async_trait;
use firestore::errors::FirestoreError;
use firestore::*;
use futures::stream::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};

use crate::config::backends::FirestoreConfig;

use super::{BilletRecord, DataStore, DataStoreError, EphemeralKeyRecord, PolicyRecord};

/// Firestore document model for billets.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirestoreBilletDoc {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Firestore document model for policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirestorePolicyDoc {
    pub billet_name: String,
    pub policy_id: String,
    pub statement: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Firestore document model for ephemeral keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirestoreKeyDoc {
    pub key_id: String,
    pub public_key_pem: String,
    pub private_key_encrypted: Vec<u8>,
    pub kms_attestation: Vec<u8>,
    pub algorithm: String,
    pub created_at: String,
    pub expires_at: String,
    pub purpose: String,
}

/// Google Cloud Firestore-backed implementation of the `DataStore` trait.
pub struct FirestoreDataStore {
    db: FirestoreDb,
    billets_collection: String,
    policies_collection: String,
    keys_collection: String,
}

impl FirestoreDataStore {
    /// Creates a new `FirestoreDataStore` from a `FirestoreConfig`.
    ///
    /// This initializes the Firestore client using Application Default Credentials
    /// or the environment-configured authentication method.
    pub async fn new(config: &FirestoreConfig) -> Result<Self, DataStoreError> {
        let db = FirestoreDb::new(&config.project)
            .await
            .map_err(|e| DataStoreError::Internal(format!("failed to initialize Firestore: {}", e)))?;

        let prefix = &config.collection_prefix;
        Ok(Self {
            db,
            billets_collection: format!("{}-billets", prefix),
            policies_collection: format!("{}-policies", prefix),
            keys_collection: format!("{}-keys", prefix),
        })
    }

    /// Construct the document ID for a policy: `{billet_name}__{policy_id}`.
    fn policy_doc_id(billet_name: &str, policy_id: &str) -> String {
        format!("{}__{}", billet_name, policy_id)
    }

    /// Construct the document ID for an ephemeral key: `{purpose}__{key_id}`.
    fn key_doc_id(purpose: &str, key_id: &str) -> String {
        format!("{}__{}", purpose, key_id)
    }

    /// Convert a `BilletRecord` to a Firestore document model.
    fn billet_to_doc(record: &BilletRecord) -> FirestoreBilletDoc {
        FirestoreBilletDoc {
            name: record.name.clone(),
            description: record.description.clone(),
            associated_aws_roles: record.associated_aws_roles.clone(),
            associated_gcp_sas: record.associated_gcp_sas.clone(),
            tags: record.tags.clone(),
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
        }
    }

    /// Convert a Firestore document model to a `BilletRecord`.
    fn doc_to_billet(doc: FirestoreBilletDoc) -> BilletRecord {
        BilletRecord {
            name: doc.name,
            description: doc.description,
            associated_aws_roles: doc.associated_aws_roles,
            associated_gcp_sas: doc.associated_gcp_sas,
            tags: doc.tags,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }

    /// Convert a `PolicyRecord` to a Firestore document model.
    fn policy_to_doc(record: &PolicyRecord) -> FirestorePolicyDoc {
        FirestorePolicyDoc {
            billet_name: record.billet_name.clone(),
            policy_id: record.policy_id.clone(),
            statement: record.statement.clone(),
            description: record.description.clone(),
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
        }
    }

    /// Convert a Firestore document model to a `PolicyRecord`.
    fn doc_to_policy(doc: FirestorePolicyDoc) -> PolicyRecord {
        PolicyRecord {
            billet_name: doc.billet_name,
            policy_id: doc.policy_id,
            statement: doc.statement,
            description: doc.description,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }

    /// Convert an `EphemeralKeyRecord` to a Firestore document model.
    fn key_to_doc(record: &EphemeralKeyRecord) -> FirestoreKeyDoc {
        FirestoreKeyDoc {
            key_id: record.key_id.clone(),
            public_key_pem: record.public_key_pem.clone(),
            private_key_encrypted: record.private_key_encrypted.clone(),
            kms_attestation: record.kms_attestation.clone(),
            algorithm: record.algorithm.clone(),
            created_at: record.created_at.clone(),
            expires_at: record.expires_at.clone(),
            purpose: record.purpose.clone(),
        }
    }

    /// Convert a Firestore document model to an `EphemeralKeyRecord`.
    fn doc_to_key(doc: FirestoreKeyDoc) -> EphemeralKeyRecord {
        EphemeralKeyRecord {
            key_id: doc.key_id,
            public_key_pem: doc.public_key_pem,
            private_key_encrypted: doc.private_key_encrypted,
            kms_attestation: doc.kms_attestation,
            algorithm: doc.algorithm,
            created_at: doc.created_at,
            expires_at: doc.expires_at,
            purpose: doc.purpose,
        }
    }
}

/// Map Firestore errors to `DataStoreError`.
fn map_firestore_error(err: FirestoreError) -> DataStoreError {
    let msg = err.to_string();
    if msg.contains("NOT_FOUND") || msg.contains("NotFound") {
        DataStoreError::NotFound(msg)
    } else if msg.contains("ALREADY_EXISTS") || msg.contains("AlreadyExists") {
        DataStoreError::Conflict(msg)
    } else {
        DataStoreError::Internal(msg)
    }
}

#[async_trait]
impl DataStore for FirestoreDataStore {
    // ── Billet Operations ──

    async fn create_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        // Check if billet already exists to provide conflict semantics
        let existing: Option<FirestoreBilletDoc> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.billets_collection)
            .obj()
            .one(&record.name)
            .await
            .map_err(map_firestore_error)?;

        if existing.is_some() {
            return Err(DataStoreError::Conflict(format!(
                "billet '{}' already exists",
                record.name
            )));
        }

        let doc = Self::billet_to_doc(record);
        let _: FirestoreBilletDoc = self
            .db
            .fluent()
            .insert()
            .into(&self.billets_collection)
            .document_id(&record.name)
            .object(&doc)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn get_billet(&self, name: &str) -> Result<Option<BilletRecord>, DataStoreError> {
        let doc: Option<FirestoreBilletDoc> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.billets_collection)
            .obj()
            .one(name)
            .await
            .map_err(map_firestore_error)?;

        Ok(doc.map(Self::doc_to_billet))
    }

    async fn update_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        let doc = Self::billet_to_doc(record);
        let _: FirestoreBilletDoc = self
            .db
            .fluent()
            .update()
            .fields(paths!(FirestoreBilletDoc::{
                description,
                associated_aws_roles,
                associated_gcp_sas,
                tags,
                updated_at
            }))
            .in_col(&self.billets_collection)
            .document_id(&record.name)
            .object(&doc)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn delete_billet_cascade(&self, name: &str) -> Result<u32, DataStoreError> {
        // Query all policies for this billet
        let policies: Vec<FirestorePolicyDoc> = self
            .db
            .fluent()
            .select()
            .from(self.policies_collection.as_str())
            .filter(|q| {
                q.for_all([q
                    .field(path!(FirestorePolicyDoc::billet_name))
                    .eq(name)])
            })
            .obj()
            .stream_query_with_errors()
            .await
            .map_err(map_firestore_error)?
            .try_collect()
            .await
            .map_err(map_firestore_error)?;

        let policy_count = policies.len() as u32;

        // Delete policies in batches of 500 (Firestore batch limit)
        for chunk in policies.chunks(500) {
            let mut batch = self
                .db
                .begin_transaction()
                .await
                .map_err(map_firestore_error)?;

            for policy in chunk {
                let doc_id = Self::policy_doc_id(&policy.billet_name, &policy.policy_id);
                self.db
                    .fluent()
                    .delete()
                    .from(self.policies_collection.as_str())
                    .document_id(&doc_id)
                    .add_to_transaction(&mut batch)
                    .map_err(map_firestore_error)?;
            }

            // Also delete the billet itself in the last batch
            // (We'll add it outside the loop to avoid duplicates if there are exactly N*500 policies)
            batch.commit().await.map_err(map_firestore_error)?;
        }

        // Delete the billet document itself
        // If there were no policies, we still need to handle the empty-chunk case
        self.db
            .fluent()
            .delete()
            .from(self.billets_collection.as_str())
            .document_id(name)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        // Return count: policies + the billet itself
        Ok(policy_count + 1)
    }

    async fn list_billets(&self) -> Result<Vec<BilletRecord>, DataStoreError> {
        let docs: Vec<FirestoreBilletDoc> = self
            .db
            .fluent()
            .list()
            .from(self.billets_collection.as_str())
            .obj()
            .stream_all()
            .await
            .map_err(map_firestore_error)?
            .collect()
            .await;

        Ok(docs.into_iter().map(Self::doc_to_billet).collect())
    }

    // ── Policy Operations ──

    async fn create_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        let doc_id = Self::policy_doc_id(&record.billet_name, &record.policy_id);

        // Check if policy already exists for conflict semantics
        let existing: Option<FirestorePolicyDoc> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.policies_collection)
            .obj()
            .one(&doc_id)
            .await
            .map_err(map_firestore_error)?;

        if existing.is_some() {
            return Err(DataStoreError::Conflict(format!(
                "policy '{}/{}' already exists",
                record.billet_name, record.policy_id
            )));
        }

        let doc = Self::policy_to_doc(record);
        let _: FirestorePolicyDoc = self
            .db
            .fluent()
            .insert()
            .into(&self.policies_collection)
            .document_id(&doc_id)
            .object(&doc)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DataStoreError> {
        let doc_id = Self::policy_doc_id(billet_name, policy_id);

        let doc: Option<FirestorePolicyDoc> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.policies_collection)
            .obj()
            .one(&doc_id)
            .await
            .map_err(map_firestore_error)?;

        Ok(doc.map(Self::doc_to_policy))
    }

    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        let doc_id = Self::policy_doc_id(&record.billet_name, &record.policy_id);
        let doc = Self::policy_to_doc(record);

        let _: FirestorePolicyDoc = self
            .db
            .fluent()
            .update()
            .fields(paths!(FirestorePolicyDoc::{
                statement,
                description,
                updated_at
            }))
            .in_col(&self.policies_collection)
            .document_id(&doc_id)
            .object(&doc)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DataStoreError> {
        let doc_id = Self::policy_doc_id(billet_name, policy_id);

        self.db
            .fluent()
            .delete()
            .from(self.policies_collection.as_str())
            .document_id(&doc_id)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn list_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<PolicyRecord>, DataStoreError> {
        let docs: Vec<FirestorePolicyDoc> = self
            .db
            .fluent()
            .select()
            .from(self.policies_collection.as_str())
            .filter(|q| {
                q.for_all([q
                    .field(path!(FirestorePolicyDoc::billet_name))
                    .eq(billet_name)])
            })
            .obj()
            .stream_query_with_errors()
            .await
            .map_err(map_firestore_error)?
            .try_collect()
            .await
            .map_err(map_firestore_error)?;

        Ok(docs.into_iter().map(Self::doc_to_policy).collect())
    }

    async fn list_all_policies(&self) -> Result<Vec<PolicyRecord>, DataStoreError> {
        let docs: Vec<FirestorePolicyDoc> = self
            .db
            .fluent()
            .list()
            .from(self.policies_collection.as_str())
            .obj()
            .stream_all()
            .await
            .map_err(map_firestore_error)?
            .collect()
            .await;

        Ok(docs.into_iter().map(Self::doc_to_policy).collect())
    }

    // ── Ephemeral Key Operations ──

    async fn put_ephemeral_key(&self, record: &EphemeralKeyRecord) -> Result<(), DataStoreError> {
        let doc_id = Self::key_doc_id(&record.purpose, &record.key_id);
        let doc = Self::key_to_doc(record);

        // Use update (upsert) semantics for ephemeral keys
        let _: FirestoreKeyDoc = self
            .db
            .fluent()
            .update()
            .fields(paths!(FirestoreKeyDoc::{
                key_id,
                public_key_pem,
                private_key_encrypted,
                kms_attestation,
                algorithm,
                created_at,
                expires_at,
                purpose
            }))
            .in_col(&self.keys_collection)
            .document_id(&doc_id)
            .object(&doc)
            .execute()
            .await
            .map_err(map_firestore_error)?;

        Ok(())
    }

    async fn get_active_ephemeral_keys(
        &self,
        purpose: &str,
    ) -> Result<Vec<EphemeralKeyRecord>, DataStoreError> {
        let now = chrono::Utc::now().to_rfc3339();

        let docs: Vec<FirestoreKeyDoc> = self
            .db
            .fluent()
            .select()
            .from(self.keys_collection.as_str())
            .filter(|q| {
                q.for_all([
                    q.field(path!(FirestoreKeyDoc::purpose)).eq(purpose),
                    q.field(path!(FirestoreKeyDoc::expires_at))
                        .greater_than(now.as_str()),
                ])
            })
            .obj()
            .stream_query_with_errors()
            .await
            .map_err(map_firestore_error)?
            .try_collect()
            .await
            .map_err(map_firestore_error)?;

        Ok(docs.into_iter().map(Self::doc_to_key).collect())
    }

    async fn delete_expired_ephemeral_keys(
        &self,
        purpose: &str,
        before: &str,
    ) -> Result<u32, DataStoreError> {
        // Query expired keys
        let docs: Vec<FirestoreKeyDoc> = self
            .db
            .fluent()
            .select()
            .from(self.keys_collection.as_str())
            .filter(|q| {
                q.for_all([
                    q.field(path!(FirestoreKeyDoc::purpose)).eq(purpose),
                    q.field(path!(FirestoreKeyDoc::expires_at))
                        .less_than_or_equal(before),
                ])
            })
            .obj()
            .stream_query_with_errors()
            .await
            .map_err(map_firestore_error)?
            .try_collect()
            .await
            .map_err(map_firestore_error)?;

        let count = docs.len() as u32;

        // Delete expired keys in batches of 500
        for chunk in docs.chunks(500) {
            let mut batch = self
                .db
                .begin_transaction()
                .await
                .map_err(map_firestore_error)?;

            for key_doc in chunk {
                let doc_id = Self::key_doc_id(&key_doc.purpose, &key_doc.key_id);
                self.db
                    .fluent()
                    .delete()
                    .from(self.keys_collection.as_str())
                    .document_id(&doc_id)
                    .add_to_transaction(&mut batch)
                    .map_err(map_firestore_error)?;
            }

            batch.commit().await.map_err(map_firestore_error)?;
        }

        Ok(count)
    }

    // ── Health ──

    async fn ping(&self) -> Result<(), DataStoreError> {
        // Attempt to list a single document from the billets collection to verify connectivity
        let _: Vec<FirestoreBilletDoc> = self
            .db
            .fluent()
            .list()
            .from(self.billets_collection.as_str())
            .page_size(1)
            .obj()
            .stream_all()
            .await
            .map_err(map_firestore_error)?
            .collect()
            .await;

        Ok(())
    }
}
