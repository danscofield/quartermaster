// PolicySyncService — background task that syncs Cedar policies from DynamoDB.

use std::collections::HashSet;
use std::sync::Arc;

use cedar_policy::PolicySet;
use regex::Regex;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::dynamo::{DynamoClient, PolicyRecord};

/// PolicySyncState holds the atomically-swappable policy state.
#[derive(Debug, Clone)]
pub struct PolicySyncState {
    pub policy_set: PolicySet,
    pub known_billets: HashSet<String>,
}

/// PolicySyncService runs a background task that:
/// 1. On startup: full scan of quartermaster-policies table → parse all statements into PolicySet
///    → extract known billet names
/// 2. Every `sync_interval_secs`: repeat scan and atomically swap the PolicySet and billet set
/// 3. On DynamoDB failure: continue with last successfully loaded PolicySet, log warning,
///    report degraded only if no PolicySet has ever been loaded
///
/// Billet names are derived by parsing all policies and extracting every `Billet::"X"` entity ID
/// referenced in resource scopes.
pub struct PolicySyncService {
    state: Arc<RwLock<Option<PolicySyncState>>>,
    /// A separate policy_set handle that the CedarAuthorizer can reference directly.
    policy_set_handle: Arc<RwLock<Option<PolicySet>>>,
    dynamo_client: Arc<dyn DynamoClient>,
    sync_interval_secs: u64,
}

impl PolicySyncService {
    /// Create a new PolicySyncService.
    pub fn new(dynamo_client: Arc<dyn DynamoClient>, sync_interval_secs: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(None)),
            policy_set_handle: Arc::new(RwLock::new(None)),
            dynamo_client,
            sync_interval_secs,
        }
    }

    /// Returns the shared `Arc<RwLock<Option<PolicySet>>>` that can be passed to
    /// the CedarAuthorizer for in-process policy evaluation.
    pub fn policy_set_handle(&self) -> Arc<RwLock<Option<PolicySet>>> {
        Arc::clone(&self.policy_set_handle)
    }

    /// Returns true if a PolicySet has been loaded at least once (first sync succeeded).
    pub async fn is_initialized(&self) -> bool {
        self.state.read().await.is_some()
    }

    /// Returns the current known billet names (derived from policies).
    /// Returns an empty set if no policies have been loaded yet.
    pub async fn known_billets(&self) -> HashSet<String> {
        match self.state.read().await.as_ref() {
            Some(state) => state.known_billets.clone(),
            None => HashSet::new(),
        }
    }

    /// Returns a clone of the current PolicySet for evaluation.
    pub async fn policy_set(&self) -> Option<PolicySet> {
        self.state
            .read()
            .await
            .as_ref()
            .map(|s| s.policy_set.clone())
    }

    /// Performs a single sync: scans DynamoDB, parses policies, extracts billets,
    /// and atomically swaps state. Returns Ok(()) on success, Err on failure.
    async fn sync_once(&self) -> Result<(), String> {
        let records = self
            .dynamo_client
            .list_policies()
            .await
            .map_err(|e| format!("DynamoDB list_policies failed: {e}"))?;

        let (policy_set, known_billets) = Self::parse_policies(&records)?;

        // Atomically update the shared policy_set_handle for CedarAuthorizer
        {
            let mut handle = self.policy_set_handle.write().await;
            *handle = Some(policy_set.clone());
        }

        // Atomically update the full state
        {
            let mut state = self.state.write().await;
            *state = Some(PolicySyncState {
                policy_set,
                known_billets,
            });
        }

        Ok(())
    }

    /// Parse policy records into a PolicySet and extract known billet names.
    fn parse_policies(
        records: &[PolicyRecord],
    ) -> Result<(PolicySet, HashSet<String>), String> {
        // Combine all policy statements into a single string for parsing
        let combined: String = records
            .iter()
            .map(|r| r.statement.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let policy_set: PolicySet = combined
            .parse()
            .map_err(|e| format!("Failed to parse PolicySet: {e}"))?;

        // Extract billet names from all policy statements using regex
        let known_billets = Self::extract_billet_names(records);

        Ok((policy_set, known_billets))
    }

    /// Extract known billet names from policy statements by searching for
    /// `Billet::"<name>"` patterns in resource scopes.
    fn extract_billet_names(records: &[PolicyRecord]) -> HashSet<String> {
        let re = Regex::new(r#"Billet::"([^"]+)""#).expect("Invalid billet regex");
        let mut billets = HashSet::new();

        for record in records {
            for cap in re.captures_iter(&record.statement) {
                if let Some(name) = cap.get(1) {
                    billets.insert(name.as_str().to_string());
                }
            }
        }

        billets
    }

    /// Starts the background sync loop (call once at startup).
    /// Performs an initial sync immediately, then polls at the configured interval.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Initial sync
            match self.sync_once().await {
                Ok(()) => {
                    let billets = self.known_billets().await;
                    info!(
                        billet_count = billets.len(),
                        "PolicySyncService: initial sync succeeded"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "PolicySyncService: initial sync failed, service is degraded"
                    );
                }
            }

            // Background poll loop
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(self.sync_interval_secs));

            // The first tick completes immediately; skip it since we already did initial sync
            interval.tick().await;

            loop {
                interval.tick().await;

                match self.sync_once().await {
                    Ok(()) => {
                        let billets = self.known_billets().await;
                        info!(
                            billet_count = billets.len(),
                            "PolicySyncService: sync succeeded"
                        );
                    }
                    Err(e) => {
                        // On failure during poll: log warning, continue with last loaded state
                        warn!(
                            error = %e,
                            "PolicySyncService: sync failed, continuing with previous PolicySet"
                        );
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamo::{DynamoError, MockDynamoClient};

    fn make_policy_record(id: &str, statement: &str) -> PolicyRecord {
        PolicyRecord {
            policy_id: id.to_string(),
            statement: statement.to_string(),
            description: "test policy".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_extract_billet_names_single() {
        let records = vec![make_policy_record(
            "p1",
            r#"permit(principal, action, resource == Quartermaster::Billet::"payments");"#,
        )];

        let billets = PolicySyncService::extract_billet_names(&records);
        assert_eq!(billets.len(), 1);
        assert!(billets.contains("payments"));
    }

    #[test]
    fn test_extract_billet_names_multiple() {
        let records = vec![
            make_policy_record(
                "p1",
                r#"permit(principal, action, resource == Quartermaster::Billet::"payments");"#,
            ),
            make_policy_record(
                "p2",
                r#"permit(principal, action, resource in [Quartermaster::Billet::"analytics", Quartermaster::Billet::"reporting"]);"#,
            ),
        ];

        let billets = PolicySyncService::extract_billet_names(&records);
        assert_eq!(billets.len(), 3);
        assert!(billets.contains("payments"));
        assert!(billets.contains("analytics"));
        assert!(billets.contains("reporting"));
    }

    #[test]
    fn test_extract_billet_names_none() {
        let records = vec![make_policy_record(
            "p1",
            r#"permit(principal, action, resource);"#,
        )];

        let billets = PolicySyncService::extract_billet_names(&records);
        assert!(billets.is_empty());
    }

    #[test]
    fn test_extract_billet_names_deduplicates() {
        let records = vec![
            make_policy_record(
                "p1",
                r#"permit(principal, action, resource == Quartermaster::Billet::"payments");"#,
            ),
            make_policy_record(
                "p2",
                r#"permit(principal, action, resource == Quartermaster::Billet::"payments");"#,
            ),
        ];

        let billets = PolicySyncService::extract_billet_names(&records);
        assert_eq!(billets.len(), 1);
        assert!(billets.contains("payments"));
    }

    #[test]
    fn test_parse_policies_valid() {
        let records = vec![make_policy_record(
            "p1",
            r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#,
        )];

        let result = PolicySyncService::parse_policies(&records);
        assert!(result.is_ok());
        let (policy_set, billets) = result.unwrap();
        // PolicySet should have one policy
        assert_eq!(policy_set.policies().count(), 1);
        assert!(billets.contains("payments"));
    }

    #[test]
    fn test_parse_policies_invalid_cedar() {
        let records = vec![make_policy_record("p1", "this is not valid cedar")];

        let result = PolicySyncService::parse_policies(&records);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_policies_empty() {
        let records: Vec<PolicyRecord> = vec![];

        let result = PolicySyncService::parse_policies(&records);
        assert!(result.is_ok());
        let (policy_set, billets) = result.unwrap();
        assert_eq!(policy_set.policies().count(), 0);
        assert!(billets.is_empty());
    }

    #[tokio::test]
    async fn test_not_initialized_on_create() {
        let mut mock = MockDynamoClient::new();
        mock.expect_list_policies().never();

        let service = PolicySyncService::new(Arc::new(mock), 30);
        assert!(!service.is_initialized().await);
        assert!(service.known_billets().await.is_empty());
        assert!(service.policy_set().await.is_none());
    }

    #[tokio::test]
    async fn test_sync_once_success() {
        let mut mock = MockDynamoClient::new();
        mock.expect_list_policies().returning(|| {
            Ok(vec![PolicyRecord {
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });

        let service = PolicySyncService::new(Arc::new(mock), 30);
        let result = service.sync_once().await;
        assert!(result.is_ok());
        assert!(service.is_initialized().await);

        let billets = service.known_billets().await;
        assert_eq!(billets.len(), 1);
        assert!(billets.contains("payments"));

        // Verify policy_set_handle is also updated
        let handle = service.policy_set_handle();
        let ps = handle.read().await;
        assert!(ps.is_some());
    }

    #[tokio::test]
    async fn test_sync_once_dynamo_failure() {
        let mut mock = MockDynamoClient::new();
        mock.expect_list_policies()
            .returning(|| Err(DynamoError::ServiceError("connection refused".to_string())));

        let service = PolicySyncService::new(Arc::new(mock), 30);
        let result = service.sync_once().await;
        assert!(result.is_err());
        assert!(!service.is_initialized().await);
    }

    #[tokio::test]
    async fn test_sync_failure_preserves_previous_state() {
        let mut mock = MockDynamoClient::new();
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        mock.expect_list_policies().returning(move || {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                // First call succeeds
                Ok(vec![PolicyRecord {
                    policy_id: "p1".to_string(),
                    statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                    description: "test".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }])
            } else {
                // Subsequent calls fail
                Err(DynamoError::ServiceError("timeout".to_string()))
            }
        });

        let service = PolicySyncService::new(Arc::new(mock), 30);

        // First sync succeeds
        let result = service.sync_once().await;
        assert!(result.is_ok());
        assert!(service.is_initialized().await);
        assert!(service.known_billets().await.contains("payments"));

        // Second sync fails — state should be preserved
        let result = service.sync_once().await;
        assert!(result.is_err());
        assert!(service.is_initialized().await);
        assert!(service.known_billets().await.contains("payments"));
    }

    #[tokio::test]
    async fn test_policy_set_handle_accessible() {
        let mut mock = MockDynamoClient::new();
        mock.expect_list_policies().returning(|| {
            Ok(vec![PolicyRecord {
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action, resource);"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });

        let service = PolicySyncService::new(Arc::new(mock), 30);
        let handle = service.policy_set_handle();

        // Before sync, handle should be None
        assert!(handle.read().await.is_none());

        // After sync, handle should have a PolicySet
        service.sync_once().await.unwrap();
        assert!(handle.read().await.is_some());
    }
}
