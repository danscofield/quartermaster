// Billet resolution orchestration + trait

pub mod entity_builder;
pub mod selector;

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::Decision;
use tracing::{info, warn};

use crate::cedar::{BatchAuthzRequest, CommonContext, LocalAuthorizer};
use crate::domain::cache::{Cache, CacheError};
use crate::sync::PolicySyncService;

use self::entity_builder::{EntityBuilder, EntityBuilderInput};
use self::selector::SelectorEnricher;

/// Resolution represents the outcome of billet resolution for a workload.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub billets: Vec<String>,
    pub cache_hit: bool,
}

/// ResolverInput contains the workload attributes needed for Cedar evaluation.
#[derive(Debug, Clone)]
pub struct ResolverInput {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub environment: String,
    pub region: String,
    pub audience: String,
    pub request_time: chrono::DateTime<chrono::Utc>,
    pub source_cloud: String,
    pub selectors: Vec<String>,
}

/// BilletError represents errors that can occur during billet resolution.
#[derive(Debug)]
pub enum BilletError {
    /// All Cedar decisions were Deny — maps to 403 Forbidden.
    NoBilletsResolved,
    /// PolicySet hasn't been loaded yet (first DynamoDB sync not succeeded) — maps to 503.
    PolicySetNotInitialized,
    /// Unexpected internal errors.
    InternalError(String),
}

impl std::fmt::Display for BilletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BilletError::NoBilletsResolved => write!(f, "no billets resolved (all denied)"),
            BilletError::PolicySetNotInitialized => {
                write!(f, "policy set not initialized")
            }
            BilletError::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for BilletError {}

/// Resolver determines which billets a workload holds.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve evaluates Cedar policies locally and returns the set of allowed billets.
    async fn resolve(&self, input: ResolverInput) -> Result<Resolution, BilletError>;
}

/// BilletResolverImpl orchestrates billet resolution:
/// cache check → selector enrichment → entity building → Cedar authorization → cache store.
pub struct BilletResolverImpl {
    selector_enricher: Arc<dyn SelectorEnricher>,
    entity_builder: EntityBuilder,
    authorizer: Arc<dyn LocalAuthorizer>,
    cache: Arc<dyn Cache>,
    policy_sync: Arc<PolicySyncService>,
    cache_ttl: Duration,
}

impl BilletResolverImpl {
    /// Creates a new BilletResolverImpl with all required dependencies.
    pub fn new(
        selector_enricher: Arc<dyn SelectorEnricher>,
        entity_builder: EntityBuilder,
        authorizer: Arc<dyn LocalAuthorizer>,
        cache: Arc<dyn Cache>,
        policy_sync: Arc<PolicySyncService>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            selector_enricher,
            entity_builder,
            authorizer,
            cache,
            policy_sync,
            cache_ttl,
        }
    }
}

#[async_trait::async_trait]
impl Resolver for BilletResolverImpl {
    async fn resolve(&self, input: ResolverInput) -> Result<Resolution, BilletError> {
        // Step 1: Check cache for (spiffe_id, audience)
        match self.cache.get(&input.spiffe_id, &input.audience).await {
            Ok(Some(entry)) => {
                // Cache hit — return immediately
                info!(
                    spiffe_id = %input.spiffe_id,
                    audience = %input.audience,
                    billets = entry.billets.len(),
                    "billet resolution cache hit"
                );
                return Ok(Resolution {
                    billets: entry.billets,
                    cache_hit: true,
                });
            }
            Ok(None) => {
                // Cache miss — proceed with full resolution
            }
            Err(CacheError::BackendError(msg)) => {
                // Cache backend failure — fall through to full resolution
                warn!(
                    error = %msg,
                    "cache backend failure, falling through to full resolution"
                );
            }
        }

        // Step 2: Fetch selectors from SelectorEnricher (graceful degradation built-in)
        let fetched_selectors = self
            .selector_enricher
            .fetch_selectors(&input.spiffe_id)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "selector enrichment failed, using input selectors only");
                Vec::new()
            });

        // Step 3: Combine input selectors with fetched selectors
        let mut combined_selectors = input.selectors.clone();
        for sel in fetched_selectors {
            if !combined_selectors.contains(&sel) {
                combined_selectors.push(sel);
            }
        }

        // Step 4: Build ephemeral entity via EntityBuilder
        let entity_input = EntityBuilderInput {
            spiffe_id: input.spiffe_id.clone(),
            trust_domain: input.trust_domain.clone(),
            environment: input.environment.clone(),
            region: input.region.clone(),
            selectors: combined_selectors.clone(),
        };
        let workload_entity = self.entity_builder.build(entity_input);

        // Step 5: Get known_billets from PolicySyncService
        let known_billets = self.policy_sync.known_billets().await;

        // Step 5e: If known_billets is empty and PolicySyncService is not initialized → 503
        if known_billets.is_empty() && !self.policy_sync.is_initialized().await {
            return Err(BilletError::PolicySetNotInitialized);
        }

        // If there are no known billets but service IS initialized, that means
        // there are policies but none reference billets — result will be empty → 403
        if known_billets.is_empty() {
            return Err(BilletError::NoBilletsResolved);
        }

        // Step 6: Call LocalAuthorizer::batch_is_authorized
        let resources: Vec<String> = known_billets.into_iter().collect();
        let batch_req = BatchAuthzRequest {
            principal: workload_entity,
            action: "assumeBillet".to_string(),
            resources,
            context: CommonContext {
                environment: input.environment.clone(),
                region: input.region.clone(),
                request_time: input.request_time.to_rfc3339(),
                source_cloud: input.source_cloud.clone(),
                selectors: combined_selectors,
            },
        };

        let decisions = self
            .authorizer
            .batch_is_authorized(batch_req)
            .await
            .map_err(|e| BilletError::InternalError(format!("authorization failed: {e}")))?;

        // Step 7: Filter Allow decisions → collect billet names
        let billets: Vec<String> = decisions
            .into_iter()
            .filter(|d| d.decision == Decision::Allow)
            .map(|d| d.resource)
            .collect();

        // Step 8: If no billets resolved → return NoBilletsResolved error
        if billets.is_empty() {
            return Err(BilletError::NoBilletsResolved);
        }

        // Step 9: Store result in cache
        if let Err(CacheError::BackendError(msg)) = self
            .cache
            .set(
                &input.spiffe_id,
                &input.audience,
                billets.clone(),
                self.cache_ttl,
            )
            .await
        {
            warn!(error = %msg, "failed to store billet resolution in cache");
        }

        // Step 10: Return Resolution
        info!(
            spiffe_id = %input.spiffe_id,
            audience = %input.audience,
            billets = billets.len(),
            "billet resolution completed"
        );

        Ok(Resolution {
            billets,
            cache_hit: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::{AuthzDecision, CedarError, MockLocalAuthorizer};
    use crate::domain::cache::memory::InMemoryCache;
    use crate::domain::cache::CacheEntry;
    use crate::dynamo::MockDynamoClient;
    use crate::domain::billet::selector::MockSelectorEnricher;

    fn make_input() -> ResolverInput {
        ResolverInput {
            spiffe_id: "spiffe://example.org/ns/finance/workload/payments".to_string(),
            trust_domain: "example.org".to_string(),
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            audience: "https://api.example.com".to_string(),
            request_time: chrono::Utc::now(),
            source_cloud: "aws".to_string(),
            selectors: vec!["k8s:ns:finance".to_string()],
        }
    }

    /// Helper: creates a PolicySyncService that has been initialized (sync_once called).
    async fn make_initialized_policy_sync() -> Arc<PolicySyncService> {
        use crate::dynamo::PolicyRecord;

        let mut mock_dynamo = MockDynamoClient::new();
        mock_dynamo.expect_list_policies().returning(|| {
            Ok(vec![PolicyRecord {
                policy_id: "p1".to_string(),
                statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                description: "test".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }])
        });

        let service = Arc::new(PolicySyncService::new(Arc::new(mock_dynamo), 300));
        // Start and wait for initial sync
        let handle = Arc::clone(&service).start();
        // Poll for initialization to complete
        for _ in 0..20 {
            if service.is_initialized().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
        assert!(service.is_initialized().await);
        service
    }

    /// Helper: creates a PolicySyncService that is NOT initialized.
    fn make_uninitialized_policy_sync() -> Arc<PolicySyncService> {
        let mut mock_dynamo = MockDynamoClient::new();
        mock_dynamo.expect_list_policies().never();
        Arc::new(PolicySyncService::new(Arc::new(mock_dynamo), 300))
    }

    #[tokio::test]
    async fn test_cache_hit_returns_immediately() {
        let cache = Arc::new(InMemoryCache::new());
        // Pre-populate cache
        cache
            .set(
                "spiffe://example.org/ns/finance/workload/payments",
                "https://api.example.com",
                vec!["payments".to_string(), "analytics".to_string()],
                Duration::from_secs(300),
            )
            .await
            .unwrap();

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher.expect_fetch_selectors().never();

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_batch_is_authorized().never();

        let policy_sync = make_uninitialized_policy_sync();

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await.unwrap();
        assert!(result.cache_hit);
        assert_eq!(result.billets, vec!["payments", "analytics"]);
    }

    #[tokio::test]
    async fn test_cache_miss_full_resolution_allow() {
        let cache = Arc::new(InMemoryCache::new());
        let policy_sync = make_initialized_policy_sync().await;

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec!["k8s:sa:payments-sa".to_string()]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|req| {
                Ok(req
                    .resources
                    .iter()
                    .map(|r| AuthzDecision {
                        resource: r.clone(),
                        decision: Decision::Allow,
                    })
                    .collect())
            });

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache.clone(),
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await.unwrap();
        assert!(!result.cache_hit);
        assert_eq!(result.billets, vec!["payments"]);

        // Verify cache was populated
        let cached = cache
            .get(
                "spiffe://example.org/ns/finance/workload/payments",
                "https://api.example.com",
            )
            .await
            .unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().billets, vec!["payments"]);
    }

    #[tokio::test]
    async fn test_all_deny_returns_no_billets_resolved() {
        let cache = Arc::new(InMemoryCache::new());
        let policy_sync = make_initialized_policy_sync().await;

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec![]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|req| {
                Ok(req
                    .resources
                    .iter()
                    .map(|r| AuthzDecision {
                        resource: r.clone(),
                        decision: Decision::Deny,
                    })
                    .collect())
            });

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await;
        assert!(matches!(result, Err(BilletError::NoBilletsResolved)));
    }

    #[tokio::test]
    async fn test_policy_set_not_initialized_returns_503() {
        let cache = Arc::new(InMemoryCache::new());
        let policy_sync = make_uninitialized_policy_sync();

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec![]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer.expect_batch_is_authorized().never();

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await;
        assert!(matches!(result, Err(BilletError::PolicySetNotInitialized)));
    }

    #[tokio::test]
    async fn test_cache_backend_failure_falls_through() {
        // Use a cache that always fails
        struct FailingCache;

        #[async_trait::async_trait]
        impl Cache for FailingCache {
            async fn get(
                &self,
                _spiffe_id: &str,
                _audience: &str,
            ) -> Result<Option<CacheEntry>, CacheError> {
                Err(CacheError::BackendError("connection refused".to_string()))
            }

            async fn set(
                &self,
                _spiffe_id: &str,
                _audience: &str,
                _billets: Vec<String>,
                _ttl: Duration,
            ) -> Result<(), CacheError> {
                Err(CacheError::BackendError("connection refused".to_string()))
            }

            async fn delete(
                &self,
                _spiffe_id: &str,
                _audience: &str,
            ) -> Result<(), CacheError> {
                Err(CacheError::BackendError("connection refused".to_string()))
            }
        }

        let cache = Arc::new(FailingCache);
        let policy_sync = make_initialized_policy_sync().await;

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec![]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|req| {
                Ok(req
                    .resources
                    .iter()
                    .map(|r| AuthzDecision {
                        resource: r.clone(),
                        decision: Decision::Allow,
                    })
                    .collect())
            });

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        // Should succeed despite cache failures (falls through to full resolution)
        let result = resolver.resolve(make_input()).await.unwrap();
        assert!(!result.cache_hit);
        assert_eq!(result.billets, vec!["payments"]);
    }

    #[tokio::test]
    async fn test_selector_enrichment_failure_graceful() {
        let cache = Arc::new(InMemoryCache::new());
        let policy_sync = make_initialized_policy_sync().await;

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher.expect_fetch_selectors().returning(|_| {
            Err(selector::SelectorError::ApiFailed(
                "timeout".to_string(),
            ))
        });

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|req| {
                // Verify selectors still include the input ones
                assert!(req.context.selectors.contains(&"k8s:ns:finance".to_string()));
                Ok(req
                    .resources
                    .iter()
                    .map(|r| AuthzDecision {
                        resource: r.clone(),
                        decision: Decision::Allow,
                    })
                    .collect())
            });

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        // Should still succeed with only input selectors
        let result = resolver.resolve(make_input()).await.unwrap();
        assert!(!result.cache_hit);
        assert_eq!(result.billets, vec!["payments"]);
    }

    #[tokio::test]
    async fn test_authorizer_error_returns_internal_error() {
        let cache = Arc::new(InMemoryCache::new());
        let policy_sync = make_initialized_policy_sync().await;

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec![]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|_| Err(CedarError::EvaluationFailed("boom".to_string())));

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await;
        assert!(matches!(result, Err(BilletError::InternalError(_))));
    }

    #[tokio::test]
    async fn test_mixed_decisions_filters_allow_only() {
        use crate::dynamo::PolicyRecord;

        // Create a policy sync with multiple known billets (one policy per billet)
        let mut mock_dynamo = MockDynamoClient::new();
        mock_dynamo.expect_list_policies().returning(|| {
            Ok(vec![
                PolicyRecord {
                    policy_id: "p1".to_string(),
                    statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"payments");"#.to_string(),
                    description: "test".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
                PolicyRecord {
                    policy_id: "p2".to_string(),
                    statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"analytics");"#.to_string(),
                    description: "test".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
                PolicyRecord {
                    policy_id: "p3".to_string(),
                    statement: r#"permit(principal, action == Quartermaster::Action::"assumeBillet", resource == Quartermaster::Billet::"reporting");"#.to_string(),
                    description: "test".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
            ])
        });

        let policy_sync = Arc::new(PolicySyncService::new(Arc::new(mock_dynamo), 300));
        let handle = Arc::clone(&policy_sync).start();
        // Wait for initialization to complete
        for _ in 0..20 {
            if policy_sync.is_initialized().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
        assert!(policy_sync.is_initialized().await, "PolicySyncService should be initialized");

        let cache = Arc::new(InMemoryCache::new());

        let mut mock_enricher = MockSelectorEnricher::new();
        mock_enricher
            .expect_fetch_selectors()
            .returning(|_| Ok(vec![]));

        let mut mock_authorizer = MockLocalAuthorizer::new();
        mock_authorizer
            .expect_batch_is_authorized()
            .returning(|req| {
                Ok(req
                    .resources
                    .iter()
                    .map(|r| {
                        let decision = if r == "analytics" {
                            Decision::Deny
                        } else {
                            Decision::Allow
                        };
                        AuthzDecision {
                            resource: r.clone(),
                            decision,
                        }
                    })
                    .collect())
            });

        let resolver = BilletResolverImpl::new(
            Arc::new(mock_enricher),
            EntityBuilder::new(),
            Arc::new(mock_authorizer),
            cache,
            policy_sync,
            Duration::from_secs(300),
        );

        let result = resolver.resolve(make_input()).await.unwrap();
        assert!(!result.cache_hit);
        // Should only include "payments" and "reporting", not "analytics"
        assert!(!result.billets.contains(&"analytics".to_string()));
        assert!(result.billets.contains(&"payments".to_string()));
        assert!(result.billets.contains(&"reporting".to_string()));
    }
}
