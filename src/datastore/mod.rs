pub mod dynamodb;
pub mod factory;
#[cfg(feature = "gcp")]
pub mod firestore_store;
pub mod local;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Errors from data store operations.
#[derive(Debug, Clone)]
pub enum DataStoreError {
    /// The requested item was not found.
    NotFound(String),
    /// A conflict occurred (e.g., duplicate key on create).
    Conflict(String),
    /// Backend connectivity or serialization error.
    Internal(String),
}

impl std::fmt::Display for DataStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataStoreError::NotFound(msg) => write!(f, "not found: {}", msg),
            DataStoreError::Conflict(msg) => write!(f, "conflict: {}", msg),
            DataStoreError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for DataStoreError {}

/// Billet metadata record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BilletRecord {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Policy record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRecord {
    pub billet_name: String,
    pub policy_id: String,
    pub statement: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Ephemeral key record (used by kms_delegated KeyManager).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EphemeralKeyRecord {
    pub key_id: String,
    pub public_key_pem: String,
    pub private_key_encrypted: Vec<u8>,
    pub kms_attestation: Vec<u8>,
    pub algorithm: String,
    pub created_at: String,
    pub expires_at: String,
    pub purpose: String,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DataStore: Send + Sync {
    // ── Billet Operations ──
    async fn create_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError>;
    async fn get_billet(&self, name: &str) -> Result<Option<BilletRecord>, DataStoreError>;
    async fn update_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError>;
    async fn delete_billet_cascade(&self, name: &str) -> Result<u32, DataStoreError>;
    async fn list_billets(&self) -> Result<Vec<BilletRecord>, DataStoreError>;

    // ── Policy Operations ──
    async fn create_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError>;
    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DataStoreError>;
    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError>;
    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DataStoreError>;
    async fn list_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<PolicyRecord>, DataStoreError>;
    async fn list_all_policies(&self) -> Result<Vec<PolicyRecord>, DataStoreError>;

    // ── Ephemeral Key Operations (used by kms_delegated KeyManager) ──
    async fn put_ephemeral_key(&self, record: &EphemeralKeyRecord) -> Result<(), DataStoreError>;
    async fn get_active_ephemeral_keys(
        &self,
        purpose: &str,
    ) -> Result<Vec<EphemeralKeyRecord>, DataStoreError>;
    async fn delete_expired_ephemeral_keys(
        &self,
        purpose: &str,
        before: &str,
    ) -> Result<u32, DataStoreError>;

    // ── Health ──
    async fn ping(&self) -> Result<(), DataStoreError>;
}
