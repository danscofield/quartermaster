// PolicySyncService — background task that syncs Cedar policies from DataStore.

use std::collections::HashSet;
use std::sync::Arc;

use cedar_policy::PolicySet;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::datastore::{BilletRecord, DataStore, PolicyRecord};
use crate::domain::audit::schema::{AuditEnvelope, Outcome, SyncDetails};
use crate::domain::audit::service::AuditService;

/// PolicySyncState holds the atomically-swappable policy state.
#[derive(Debug, Clone)]
pub struct PolicySyncState {
    pub policy_set: PolicySet,
    pub known_billets: HashSet<String>,
    pub billet_metadata: Vec<BilletRecord>,
}

/// PolicySyncService runs a background task that:
/// 1. On startup: full scan of policies → parse all statements into PolicySet
///    + scan billets → known billet set
/// 2. Every `sync_interval_secs`: repeat both scans and atomically swap the PolicySet and billet set
/// 3. On DataStore failure for either scan: continue with last successfully loaded state for that
///    component, log warning, report degraded only if no state has ever been loaded
///
/// Known billet names are derived from the billets table (source of truth),
/// NOT from parsing policy resource scopes.
pub struct PolicySyncService {
    state: Arc<RwLock<Option<PolicySyncState>>>,
    /// A separate policy_set handle that the CedarAuthorizer can reference directly.
    policy_set_handle: Arc<RwLock<Option<PolicySet>>>,
    data_store: Arc<dyn DataStore>,
    sync_interval_secs: u64,
    audit_service: AuditService,
}

impl PolicySyncService {
    /// Create a new PolicySyncService.
    pub fn new(data_store: Arc<dyn DataStore>, sync_interval_secs: u64, audit_service: AuditService) -> Self {
        Self {
            state: Arc::new(RwLock::new(None)),
            policy_set_handle: Arc::new(RwLock::new(None)),
            data_store,
            sync_interval_secs,
            audit_service,
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

    /// Returns the current known billet names (derived from billets table).
    /// Returns an empty set if no billets have been loaded yet.
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

    /// Returns the tags for a given billet name from cached metadata.
    /// Returns an empty vec if the billet is not found in the cache.
    pub async fn billet_tags(&self, billet_name: &str) -> Vec<String> {
        match self.state.read().await.as_ref() {
            Some(state) => state
                .billet_metadata
                .iter()
                .find(|b| b.name == billet_name)
                .map(|b| b.tags.clone())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Performs a single sync: scans DataStore policies and billets independently,
    /// parses policies, and atomically swaps state. Each scan failure is handled
    /// independently — a failure preserves the last known good state for that component.
    ///
    /// Returns Ok(()) if at least one component was updated, Err only if both scans fail
    /// and no prior state exists.
    async fn sync_once(&self) -> Result<(), String> {
        // 1. Scan all policies → build PolicySet
        let new_policy_set = match self.data_store.list_all_policies().await {
            Ok(records) => match Self::parse_policies(&records) {
                Ok(ps) => Some(ps),
                Err(e) => {
                    warn!(error = %e, "PolicySyncService: failed to parse policies, preserving last PolicySet");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "PolicySyncService: list_all_policies failed, preserving last PolicySet");
                None
            }
        };

        // 2. Scan billets → build known billet set
        let new_billet_metadata = match self.data_store.list_billets().await {
            Ok(billet_records) => Some(billet_records),
            Err(e) => {
                warn!(error = %e, "PolicySyncService: list_billets failed, preserving last known_billets");
                None
            }
        };

        // 3. Determine final state by merging new data with previous state
        let current_state = self.state.read().await.clone();

        let policy_set = match new_policy_set {
            Some(ps) => ps,
            None => match &current_state {
                Some(state) => state.policy_set.clone(),
                None => {
                    // No new data and no previous state for policies
                    if new_billet_metadata.is_none() {
                        return Err(
                            "Both list_all_policies and list_billets failed with no prior state"
                                .to_string(),
                        );
                    }
                    // We have billets but no policies — use empty PolicySet
                    "".parse::<PolicySet>().unwrap()
                }
            },
        };

        let (known_billets, billet_metadata) = match new_billet_metadata {
            Some(ref records) => {
                let billets: HashSet<String> = records.iter().map(|b| b.name.clone()).collect();
                (billets, records.clone())
            }
            None => match &current_state {
                Some(state) => (state.known_billets.clone(), state.billet_metadata.clone()),
                None => {
                    // We have policies but no billets — use empty set
                    (HashSet::new(), Vec::new())
                }
            },
        };

        // 4. Atomically update the shared policy_set_handle for CedarAuthorizer
        {
            let mut handle = self.policy_set_handle.write().await;
            *handle = Some(policy_set.clone());
        }

        // 5. Atomically update the full state
        {
            let mut state = self.state.write().await;
            *state = Some(PolicySyncState {
                policy_set,
                known_billets,
                billet_metadata,
            });
        }

        Ok(())
    }

    /// Parse policy records into a PolicySet.
    fn parse_policies(records: &[PolicyRecord]) -> Result<PolicySet, String> {
        // Combine all policy statements into a single string for parsing
        let combined: String = records
            .iter()
            .map(|r| r.statement.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let policy_set: PolicySet = combined
            .parse()
            .map_err(|e| format!("Failed to parse PolicySet: {e}"))?;

        Ok(policy_set)
    }

    /// Starts the background sync loop (call once at startup).
    /// Performs an initial sync immediately, then polls at the configured interval.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Initial sync
            let start = tokio::time::Instant::now();
            let result = self.sync_once().await;
            let duration_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(()) => {
                    let billets = self.known_billets().await;
                    let policy_set = self.policy_set().await;
                    let policy_count = policy_set.map(|ps| ps.policies().count() as u64);
                    let details = serde_json::to_value(SyncDetails {
                        policy_count,
                        billet_count: Some(billets.len() as u64),
                        duration_ms,
                    }).unwrap_or_default();
                    self.audit_service.emit(AuditEnvelope::sync_event(
                        "sync.policy.success", Outcome::Success, None, details,
                    ));
                    info!(
                        billet_count = billets.len(),
                        "PolicySyncService: initial sync succeeded"
                    );
                }
                Err(ref e) => {
                    let details = serde_json::to_value(SyncDetails {
                        policy_count: None,
                        billet_count: None,
                        duration_ms,
                    }).unwrap_or_default();
                    self.audit_service.emit(AuditEnvelope::sync_event(
                        "sync.policy.failure", Outcome::Failure, Some(e.as_str()), details,
                    ));
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

                let start = tokio::time::Instant::now();
                let result = self.sync_once().await;
                let duration_ms = start.elapsed().as_millis() as u64;

                match result {
                    Ok(()) => {
                        let billets = self.known_billets().await;
                        let policy_set = self.policy_set().await;
                        let policy_count = policy_set.map(|ps| ps.policies().count() as u64);
                        let details = serde_json::to_value(SyncDetails {
                            policy_count,
                            billet_count: Some(billets.len() as u64),
                            duration_ms,
                        }).unwrap_or_default();
                        self.audit_service.emit(AuditEnvelope::sync_event(
                            "sync.policy.success", Outcome::Success, None, details,
                        ));
                        info!(
                            billet_count = billets.len(),
                            "PolicySyncService: sync succeeded"
                        );
                    }
                    Err(ref e) => {
                        let details = serde_json::to_value(SyncDetails {
                            policy_count: None,
                            billet_count: None,
                            duration_ms,
                        }).unwrap_or_default();
                        self.audit_service.emit(AuditEnvelope::sync_event(
                            "sync.policy.failure", Outcome::Failure, Some(e.as_str()), details,
                        ));
                        // On failure during poll: log warning, continue with last loaded state
                        warn!(
                            error = %e,
                            "PolicySyncService: sync failed, continuing with previous state"
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
    use crate::datastore::{BilletRecord, DataStoreError, MockDataStore, PolicyRecord};
    use crate::domain::audit::service::AuditService;

    fn test_audit_service() -> AuditService {
        AuditService::new(vec![], 100)
    }

    fn make_policy_record(id: &str, statement: &str) -> PolicyRecord {
        PolicyRecord {
            billet_name: "default".to_string(),
            policy_id: id.to_string(),
            statement: statement.to_string(),
            description: "test policy".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn make_billet_record(name: &str, description: &str) -> BilletRecord {
        BilletRecord {
            name: name.to_string(),
            description: description.to_string(),
            associated_aws_roles: vec![],
            associated_gcp_sas: vec![],
            tags: vec![],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_parse_policies_valid() {
        let records = vec![make_policy_record(
            "p1",
            r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#,
        )];

        let result = PolicySyncService::parse_policies(&records);
        assert!(result.is_ok());
        let policy_set = result.unwrap();
        assert_eq!(policy_set.policies().count(), 1);
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
        let policy_set = result.unwrap();
        assert_eq!(policy_set.policies().count(), 0);
    }

    #[tokio::test]
    async fn test_not_initialized_on_create() {
        let mut mock = MockDataStore::new();
        mock.expect_list_all_policies().never();
        mock.expect_list_billets().never();

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());
        assert!(!service.is_initialized().await);
        assert!(service.known_billets().await.is_empty());
        assert!(service.policy_set().await.is_none());
    }

    #[tokio::test]
    async fn test_sync_once_success() {
        let mut mock = MockDataStore::new();
        mock.expect_list_all_policies().returning(|| {
            Ok(vec![PolicyRecord {
                billet_name: "payments".to_string(),
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });
        mock.expect_list_billets().returning(|| {
            Ok(vec![
                BilletRecord {
                    name: "payments".to_string(),
                    description: "payments billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
                BilletRecord {
                    name: "analytics".to_string(),
                    description: "analytics billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
            ])
        });

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());
        let result = service.sync_once().await;
        assert!(result.is_ok());
        assert!(service.is_initialized().await);

        // known_billets comes from the billets table, not policy parsing
        let billets = service.known_billets().await;
        assert_eq!(billets.len(), 2);
        assert!(billets.contains("payments"));
        assert!(billets.contains("analytics"));

        // Verify policy_set_handle is also updated
        let handle = service.policy_set_handle();
        let ps = handle.read().await;
        assert!(ps.is_some());
    }

    #[tokio::test]
    async fn test_sync_once_both_fail_no_prior_state() {
        let mut mock = MockDataStore::new();
        mock.expect_list_all_policies()
            .returning(|| Err(DataStoreError::Internal("connection refused".to_string())));
        mock.expect_list_billets()
            .returning(|| Err(DataStoreError::Internal("connection refused".to_string())));

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());
        let result = service.sync_once().await;
        assert!(result.is_err());
        assert!(!service.is_initialized().await);
    }

    #[tokio::test]
    async fn test_sync_once_policy_scan_fails_preserves_last_policy_set() {
        let mut mock = MockDataStore::new();
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        mock.expect_list_all_policies().returning(move || {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                Ok(vec![PolicyRecord {
                    billet_name: "payments".to_string(),
                    policy_id: "p1".to_string(),
                    statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                    description: "test".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }])
            } else {
                Err(DataStoreError::Internal("timeout".to_string()))
            }
        });

        mock.expect_list_billets().returning(|| {
            Ok(vec![make_billet_record("payments", "payments billet")])
        });

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());

        // First sync succeeds fully
        let result = service.sync_once().await;
        assert!(result.is_ok());
        assert!(service.is_initialized().await);
        let ps = service.policy_set().await.unwrap();
        assert_eq!(ps.policies().count(), 1);

        // Second sync: policy scan fails, but billets scan succeeds
        // Policy set should be preserved from prior state
        let result = service.sync_once().await;
        assert!(result.is_ok());
        let ps = service.policy_set().await.unwrap();
        assert_eq!(ps.policies().count(), 1); // preserved
        assert!(service.known_billets().await.contains("payments"));
    }

    #[tokio::test]
    async fn test_sync_once_billet_scan_fails_preserves_last_known_billets() {
        let mut mock = MockDataStore::new();
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        mock.expect_list_all_policies().returning(|| {
            Ok(vec![PolicyRecord {
                billet_name: "payments".to_string(),
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });

        mock.expect_list_billets().returning(move || {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                Ok(vec![
                    make_billet_record("payments", "payments billet"),
                    make_billet_record("analytics", "analytics billet"),
                ])
            } else {
                Err(DataStoreError::Internal("timeout".to_string()))
            }
        });

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());

        // First sync succeeds fully
        let result = service.sync_once().await;
        assert!(result.is_ok());
        let billets = service.known_billets().await;
        assert_eq!(billets.len(), 2);

        // Second sync: billet scan fails, policy scan succeeds
        // Known billets should be preserved from prior state
        let result = service.sync_once().await;
        assert!(result.is_ok());
        let billets = service.known_billets().await;
        assert_eq!(billets.len(), 2); // preserved
        assert!(billets.contains("payments"));
        assert!(billets.contains("analytics"));
    }

    #[tokio::test]
    async fn test_known_billets_from_billets_table_not_policies() {
        let mut mock = MockDataStore::new();

        // Policies reference "payments" billet
        mock.expect_list_all_policies().returning(|| {
            Ok(vec![PolicyRecord {
                billet_name: "payments".to_string(),
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });

        // But the billets table has "analytics" and "reporting" (NOT "payments")
        mock.expect_list_billets().returning(|| {
            Ok(vec![
                BilletRecord {
                    name: "analytics".to_string(),
                    description: "analytics billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
                BilletRecord {
                    name: "reporting".to_string(),
                    description: "reporting billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec![],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
            ])
        });

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());
        service.sync_once().await.unwrap();

        // known_billets should come from the billets table, NOT from policies
        let billets = service.known_billets().await;
        assert_eq!(billets.len(), 2);
        assert!(billets.contains("analytics"));
        assert!(billets.contains("reporting"));
        // "payments" is NOT in known_billets because it's not in the billets table
        assert!(!billets.contains("payments"));
    }

    #[tokio::test]
    async fn test_policy_set_handle_accessible() {
        let mut mock = MockDataStore::new();
        mock.expect_list_all_policies().returning(|| {
            Ok(vec![PolicyRecord {
                billet_name: "default".to_string(),
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action, resource);"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });
        mock.expect_list_billets().returning(|| Ok(vec![]));

        let service = PolicySyncService::new(Arc::new(mock), 30, test_audit_service());
        let handle = service.policy_set_handle();

        // Before sync, handle should be None
        assert!(handle.read().await.is_none());

        // After sync, handle should have a PolicySet
        service.sync_once().await.unwrap();
        assert!(handle.read().await.is_some());
    }
}
