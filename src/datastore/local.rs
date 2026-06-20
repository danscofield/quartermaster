use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{BilletRecord, DataStore, DataStoreError, EphemeralKeyRecord, PolicyRecord};

/// In-memory state backing the local file DataStore.
struct LocalState {
    billets: HashMap<String, BilletRecord>,
    policies: HashMap<(String, String), PolicyRecord>,
    keys: Vec<EphemeralKeyRecord>,
}

/// A file-backed DataStore implementation using an in-memory write-through cache.
///
/// Directory layout:
/// - `{path}/billets/{name}.json`
/// - `{path}/policies/{billet_name}/{policy_id}.json`
/// - `{path}/keys/`
pub struct LocalDataStore {
    path: PathBuf,
    state: RwLock<LocalState>,
}

impl LocalDataStore {
    /// Create a new `LocalDataStore` rooted at `path`.
    ///
    /// Creates the directory structure if it doesn't exist and loads any
    /// existing JSON files into memory.
    pub async fn new(path: PathBuf) -> Result<Self, DataStoreError> {
        // Ensure directories exist.
        let billets_dir = path.join("billets");
        let policies_dir = path.join("policies");
        let keys_dir = path.join("keys");

        tokio::fs::create_dir_all(&billets_dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("failed to create billets dir: {e}")))?;
        tokio::fs::create_dir_all(&policies_dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("failed to create policies dir: {e}")))?;
        tokio::fs::create_dir_all(&keys_dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("failed to create keys dir: {e}")))?;

        // Load existing data from disk.
        let billets = Self::load_billets(&billets_dir).await?;
        let policies = Self::load_policies(&policies_dir).await?;
        let keys = Self::load_keys(&keys_dir).await?;

        let state = LocalState {
            billets,
            policies,
            keys,
        };

        Ok(Self {
            path,
            state: RwLock::new(state),
        })
    }

    /// Load all billet JSON files from disk into a HashMap.
    async fn load_billets(
        dir: &PathBuf,
    ) -> Result<HashMap<String, BilletRecord>, DataStoreError> {
        let mut billets = HashMap::new();
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("read billets dir: {e}")))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DataStoreError::Internal(format!("read billets entry: {e}")))?
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let data = tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| DataStoreError::Internal(format!("read billet file: {e}")))?;
                let record: BilletRecord = serde_json::from_str(&data)
                    .map_err(|e| DataStoreError::Internal(format!("parse billet JSON: {e}")))?;
                billets.insert(record.name.clone(), record);
            }
        }
        Ok(billets)
    }

    /// Load all policy JSON files from disk into a HashMap.
    async fn load_policies(
        dir: &PathBuf,
    ) -> Result<HashMap<(String, String), PolicyRecord>, DataStoreError> {
        let mut policies = HashMap::new();
        let mut billet_dirs = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("read policies dir: {e}")))?;

        while let Some(billet_entry) = billet_dirs
            .next_entry()
            .await
            .map_err(|e| DataStoreError::Internal(format!("read policies billet entry: {e}")))?
        {
            let billet_path = billet_entry.path();
            if !billet_path.is_dir() {
                continue;
            }

            let mut policy_entries = tokio::fs::read_dir(&billet_path)
                .await
                .map_err(|e| DataStoreError::Internal(format!("read policy dir: {e}")))?;

            while let Some(policy_entry) = policy_entries
                .next_entry()
                .await
                .map_err(|e| DataStoreError::Internal(format!("read policy entry: {e}")))?
            {
                let policy_path = policy_entry.path();
                if policy_path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let data = tokio::fs::read_to_string(&policy_path)
                        .await
                        .map_err(|e| {
                            DataStoreError::Internal(format!("read policy file: {e}"))
                        })?;
                    let record: PolicyRecord = serde_json::from_str(&data).map_err(|e| {
                        DataStoreError::Internal(format!("parse policy JSON: {e}"))
                    })?;
                    policies.insert(
                        (record.billet_name.clone(), record.policy_id.clone()),
                        record,
                    );
                }
            }
        }
        Ok(policies)
    }

    /// Load all ephemeral key JSON files from disk.
    async fn load_keys(dir: &PathBuf) -> Result<Vec<EphemeralKeyRecord>, DataStoreError> {
        let mut keys = Vec::new();
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| DataStoreError::Internal(format!("read keys dir: {e}")))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DataStoreError::Internal(format!("read keys entry: {e}")))?
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let data = tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| DataStoreError::Internal(format!("read key file: {e}")))?;
                let record: EphemeralKeyRecord = serde_json::from_str(&data)
                    .map_err(|e| DataStoreError::Internal(format!("parse key JSON: {e}")))?;
                keys.push(record);
            }
        }
        Ok(keys)
    }

    /// Atomically write JSON data to a file (write to temp, then rename).
    async fn atomic_write(path: &PathBuf, data: &[u8]) -> Result<(), DataStoreError> {
        let temp_path = path.with_extension("json.tmp");

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| DataStoreError::Internal(format!("create parent dir: {e}")))?;
        }

        tokio::fs::write(&temp_path, data)
            .await
            .map_err(|e| DataStoreError::Internal(format!("write temp file: {e}")))?;

        tokio::fs::rename(&temp_path, path)
            .await
            .map_err(|e| DataStoreError::Internal(format!("rename temp file: {e}")))?;

        Ok(())
    }

    /// Get the file path for a billet record.
    fn billet_path(&self, name: &str) -> PathBuf {
        self.path.join("billets").join(format!("{name}.json"))
    }

    /// Get the file path for a policy record.
    fn policy_path(&self, billet_name: &str, policy_id: &str) -> PathBuf {
        self.path
            .join("policies")
            .join(billet_name)
            .join(format!("{policy_id}.json"))
    }

    /// Get the file path for an ephemeral key record.
    fn key_path(&self, key_id: &str) -> PathBuf {
        self.path.join("keys").join(format!("{key_id}.json"))
    }
}

#[async_trait]
impl DataStore for LocalDataStore {
    // ── Billet Operations ──

    async fn create_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        if state.billets.contains_key(&record.name) {
            return Err(DataStoreError::Conflict(format!(
                "billet '{}' already exists",
                record.name
            )));
        }

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| DataStoreError::Internal(format!("serialize billet: {e}")))?;
        let path = self.billet_path(&record.name);
        Self::atomic_write(&path, &json).await?;

        state.billets.insert(record.name.clone(), record.clone());
        Ok(())
    }

    async fn get_billet(&self, name: &str) -> Result<Option<BilletRecord>, DataStoreError> {
        let state = self.state.read().await;
        Ok(state.billets.get(name).cloned())
    }

    async fn update_billet(&self, record: &BilletRecord) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        if !state.billets.contains_key(&record.name) {
            return Err(DataStoreError::NotFound(format!(
                "billet '{}' not found",
                record.name
            )));
        }

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| DataStoreError::Internal(format!("serialize billet: {e}")))?;
        let path = self.billet_path(&record.name);
        Self::atomic_write(&path, &json).await?;

        state.billets.insert(record.name.clone(), record.clone());
        Ok(())
    }

    async fn delete_billet_cascade(&self, name: &str) -> Result<u32, DataStoreError> {
        let mut state = self.state.write().await;

        // Remove the billet itself.
        if state.billets.remove(name).is_none() {
            return Err(DataStoreError::NotFound(format!(
                "billet '{}' not found",
                name
            )));
        }

        // Count and remove all policies for this billet from memory.
        let policy_keys: Vec<(String, String)> = state
            .policies
            .keys()
            .filter(|(billet_name, _)| billet_name == name)
            .cloned()
            .collect();
        let policy_count = policy_keys.len() as u32;
        for key in &policy_keys {
            state.policies.remove(key);
        }

        // Remove billet JSON file from disk.
        let billet_path = self.billet_path(name);
        let _ = tokio::fs::remove_file(&billet_path).await;

        // Remove the entire policies directory for this billet.
        let policies_dir = self.path.join("policies").join(name);
        let _ = tokio::fs::remove_dir_all(&policies_dir).await;

        // Return count of deleted policies + 1 (for the billet itself).
        Ok(policy_count + 1)
    }

    async fn list_billets(&self) -> Result<Vec<BilletRecord>, DataStoreError> {
        let state = self.state.read().await;
        Ok(state.billets.values().cloned().collect())
    }

    // ── Policy Operations ──

    async fn create_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        let key = (record.billet_name.clone(), record.policy_id.clone());
        if state.policies.contains_key(&key) {
            return Err(DataStoreError::Conflict(format!(
                "policy '{}/{}' already exists",
                record.billet_name, record.policy_id
            )));
        }

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| DataStoreError::Internal(format!("serialize policy: {e}")))?;
        let path = self.policy_path(&record.billet_name, &record.policy_id);
        Self::atomic_write(&path, &json).await?;

        state.policies.insert(key, record.clone());
        Ok(())
    }

    async fn get_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, DataStoreError> {
        let state = self.state.read().await;
        let key = (billet_name.to_string(), policy_id.to_string());
        Ok(state.policies.get(&key).cloned())
    }

    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        let key = (record.billet_name.clone(), record.policy_id.clone());
        if !state.policies.contains_key(&key) {
            return Err(DataStoreError::NotFound(format!(
                "policy '{}/{}' not found",
                record.billet_name, record.policy_id
            )));
        }

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| DataStoreError::Internal(format!("serialize policy: {e}")))?;
        let path = self.policy_path(&record.billet_name, &record.policy_id);
        Self::atomic_write(&path, &json).await?;

        state.policies.insert(key, record.clone());
        Ok(())
    }

    async fn delete_policy(
        &self,
        billet_name: &str,
        policy_id: &str,
    ) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        let key = (billet_name.to_string(), policy_id.to_string());
        if state.policies.remove(&key).is_none() {
            return Err(DataStoreError::NotFound(format!(
                "policy '{billet_name}/{policy_id}' not found"
            )));
        }

        let path = self.policy_path(billet_name, policy_id);
        let _ = tokio::fs::remove_file(&path).await;

        Ok(())
    }

    async fn list_policies_for_billet(
        &self,
        billet_name: &str,
    ) -> Result<Vec<PolicyRecord>, DataStoreError> {
        let state = self.state.read().await;
        let policies: Vec<PolicyRecord> = state
            .policies
            .iter()
            .filter(|((bn, _), _)| bn == billet_name)
            .map(|(_, record)| record.clone())
            .collect();
        Ok(policies)
    }

    async fn list_all_policies(&self) -> Result<Vec<PolicyRecord>, DataStoreError> {
        let state = self.state.read().await;
        Ok(state.policies.values().cloned().collect())
    }

    // ── Ephemeral Key Operations ──

    async fn put_ephemeral_key(&self, record: &EphemeralKeyRecord) -> Result<(), DataStoreError> {
        let mut state = self.state.write().await;

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| DataStoreError::Internal(format!("serialize key: {e}")))?;
        let path = self.key_path(&record.key_id);
        Self::atomic_write(&path, &json).await?;

        // Replace if key_id already exists, otherwise push.
        if let Some(existing) = state.keys.iter_mut().find(|k| k.key_id == record.key_id) {
            *existing = record.clone();
        } else {
            state.keys.push(record.clone());
        }

        Ok(())
    }

    async fn get_active_ephemeral_keys(
        &self,
        purpose: &str,
    ) -> Result<Vec<EphemeralKeyRecord>, DataStoreError> {
        let state = self.state.read().await;
        let now = chrono::Utc::now().to_rfc3339();
        let active: Vec<EphemeralKeyRecord> = state
            .keys
            .iter()
            .filter(|k| k.purpose == purpose && k.expires_at > now)
            .cloned()
            .collect();
        Ok(active)
    }

    async fn delete_expired_ephemeral_keys(
        &self,
        purpose: &str,
        before: &str,
    ) -> Result<u32, DataStoreError> {
        let mut state = self.state.write().await;

        let mut deleted = 0u32;
        let mut to_remove_ids = Vec::new();

        for key in state.keys.iter() {
            if key.purpose == purpose && key.expires_at.as_str() <= before {
                to_remove_ids.push(key.key_id.clone());
            }
        }

        for key_id in &to_remove_ids {
            let path = self.key_path(key_id);
            let _ = tokio::fs::remove_file(&path).await;
            deleted += 1;
        }

        state
            .keys
            .retain(|k| !(k.purpose == purpose && k.expires_at.as_str() <= before));

        Ok(deleted)
    }

    // ── Health ──

    async fn ping(&self) -> Result<(), DataStoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_billet(name: &str) -> BilletRecord {
        BilletRecord {
            name: name.to_string(),
            description: format!("Test billet {name}"),
            associated_aws_roles: vec!["arn:aws:iam::123:role/test".to_string()],
            associated_gcp_sas: vec![],
            tags: vec!["test".to_string()],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn test_policy(billet_name: &str, policy_id: &str) -> PolicyRecord {
        PolicyRecord {
            billet_name: billet_name.to_string(),
            policy_id: policy_id.to_string(),
            statement: "permit(principal, action, resource);".to_string(),
            description: format!("Test policy {policy_id}"),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn test_billet_crud_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let billet = test_billet("payments");

        // Create
        store.create_billet(&billet).await.unwrap();

        // Read
        let fetched = store.get_billet("payments").await.unwrap().unwrap();
        assert_eq!(fetched, billet);

        // Update
        let mut updated = billet.clone();
        updated.description = "Updated description".to_string();
        updated.updated_at = "2024-01-02T00:00:00Z".to_string();
        store.update_billet(&updated).await.unwrap();

        let fetched = store.get_billet("payments").await.unwrap().unwrap();
        assert_eq!(fetched.description, "Updated description");

        // List
        let all = store.list_billets().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_billet_create_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let billet = test_billet("payments");
        store.create_billet(&billet).await.unwrap();

        let result = store.create_billet(&billet).await;
        assert!(matches!(result, Err(DataStoreError::Conflict(_))));
    }

    #[tokio::test]
    async fn test_billet_update_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let billet = test_billet("nonexistent");
        let result = store.update_billet(&billet).await;
        assert!(matches!(result, Err(DataStoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_policy_crud_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let policy = test_policy("payments", "p1");

        // Create
        store.create_policy(&policy).await.unwrap();

        // Read
        let fetched = store.get_policy("payments", "p1").await.unwrap().unwrap();
        assert_eq!(fetched, policy);

        // Update
        let mut updated = policy.clone();
        updated.statement = "forbid(principal, action, resource);".to_string();
        store.update_policy(&updated).await.unwrap();

        let fetched = store.get_policy("payments", "p1").await.unwrap().unwrap();
        assert_eq!(fetched.statement, "forbid(principal, action, resource);");

        // Delete
        store.delete_policy("payments", "p1").await.unwrap();
        let fetched = store.get_policy("payments", "p1").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_cascade_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let billet = test_billet("payments");
        store.create_billet(&billet).await.unwrap();

        let p1 = test_policy("payments", "p1");
        let p2 = test_policy("payments", "p2");
        store.create_policy(&p1).await.unwrap();
        store.create_policy(&p2).await.unwrap();

        // Cascade delete should remove billet + 2 policies = 3
        let count = store.delete_billet_cascade("payments").await.unwrap();
        assert_eq!(count, 3);

        // Verify everything is gone.
        assert!(store.get_billet("payments").await.unwrap().is_none());
        let policies = store.list_policies_for_billet("payments").await.unwrap();
        assert!(policies.is_empty());
    }

    #[tokio::test]
    async fn test_list_policies() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .create_policy(&test_policy("payments", "p1"))
            .await
            .unwrap();
        store
            .create_policy(&test_policy("payments", "p2"))
            .await
            .unwrap();
        store
            .create_policy(&test_policy("analytics", "p3"))
            .await
            .unwrap();

        let payments_policies = store.list_policies_for_billet("payments").await.unwrap();
        assert_eq!(payments_policies.len(), 2);

        let all_policies = store.list_all_policies().await.unwrap();
        assert_eq!(all_policies.len(), 3);
    }

    #[tokio::test]
    async fn test_ephemeral_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();

        let key = EphemeralKeyRecord {
            key_id: "key-1".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            private_key_encrypted: vec![1, 2, 3],
            kms_attestation: vec![4, 5, 6],
            algorithm: "ES256".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "2099-12-31T23:59:59Z".to_string(),
            purpose: "signing".to_string(),
        };

        store.put_ephemeral_key(&key).await.unwrap();

        let active = store.get_active_ephemeral_keys("signing").await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key_id, "key-1");

        // Expired key should not show up.
        let expired_key = EphemeralKeyRecord {
            key_id: "key-2".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            purpose: "signing".to_string(),
            ..key.clone()
        };
        store.put_ephemeral_key(&expired_key).await.unwrap();

        let active = store.get_active_ephemeral_keys("signing").await.unwrap();
        assert_eq!(active.len(), 1);

        // Delete expired.
        let deleted = store
            .delete_expired_ephemeral_keys("signing", "2024-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn test_ping() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDataStore::new(dir.path().to_path_buf()).await.unwrap();
        assert!(store.ping().await.is_ok());
    }

    #[tokio::test]
    async fn test_persistence_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        // Create data with first instance.
        {
            let store = LocalDataStore::new(path.clone()).await.unwrap();
            store.create_billet(&test_billet("payments")).await.unwrap();
            store
                .create_policy(&test_policy("payments", "p1"))
                .await
                .unwrap();
        }

        // Reload from the same directory.
        {
            let store = LocalDataStore::new(path).await.unwrap();
            let billet = store.get_billet("payments").await.unwrap();
            assert!(billet.is_some());
            let policy = store.get_policy("payments", "p1").await.unwrap();
            assert!(policy.is_some());
        }
    }
}
