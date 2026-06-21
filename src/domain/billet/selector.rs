// Selector enrichment via SPIRE Server API

use std::fmt;
use std::sync::Arc;

use crate::spireapi::SpireApiClient;

/// Error types for selector enrichment operations.
#[derive(Debug, Clone)]
pub enum SelectorError {
    /// SPIRE API call failed (connection, request, or parse error).
    ApiFailed(String),
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectorError::ApiFailed(msg) => write!(f, "selector enrichment failed: {}", msg),
        }
    }
}

impl std::error::Error for SelectorError {}

/// SelectorEnricher retrieves SPIRE workload selectors for a given SPIFFE ID.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait SelectorEnricher: Send + Sync {
    /// Fetches selectors from the SPIRE Server API for the given SPIFFE ID.
    /// Returns an empty Vec if the SPIRE Server API is unreachable or no entry exists (graceful degradation).
    async fn fetch_selectors(&self, spiffe_id: &str) -> Result<Vec<String>, SelectorError>;
}

/// Implementation of SelectorEnricher backed by the SPIRE Server API.
pub struct SpireSelectorEnricher {
    client: Arc<dyn SpireApiClient>,
}

impl SpireSelectorEnricher {
    /// Creates a new SpireSelectorEnricher with the given SPIRE API client.
    pub fn new(client: Arc<dyn SpireApiClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl SelectorEnricher for SpireSelectorEnricher {
    async fn fetch_selectors(&self, spiffe_id: &str) -> Result<Vec<String>, SelectorError> {
        match self.client.list_entries_by_spiffe_id(spiffe_id).await {
            Ok(Some(entry)) => {
                let mut selectors = entry.selectors;

                // Also fetch the parent (agent) entry's selectors for node-level metadata
                // (e.g., gcp_iit:project-id, aws:iid:account-id)
                if let Some(ref parent_id) = entry.parent_id {
                    match self.client.list_entries_by_spiffe_id(parent_id).await {
                        Ok(Some(parent_entry)) => {
                            selectors.extend(parent_entry.selectors);
                        }
                        Ok(None) => {
                            tracing::debug!("no SPIRE entry found for parent {}", parent_id);
                        }
                        Err(e) => {
                            tracing::debug!("failed to fetch parent entry {}: {}", parent_id, e);
                        }
                    }
                }

                Ok(selectors)
            }
            Ok(None) => {
                tracing::warn!("no SPIRE entry found for {}", spiffe_id);
                Ok(Vec::new())
            }
            Err(e) => {
                tracing::warn!("SPIRE API error: {}", e);
                Ok(Vec::new())
            }
        }
    }
}

/// A no-op implementation of SelectorEnricher that always returns an empty list.
/// Used when SPIRE is not configured.
pub struct NoOpSelectorEnricher;

#[async_trait::async_trait]
impl SelectorEnricher for NoOpSelectorEnricher {
    async fn fetch_selectors(&self, _spiffe_id: &str) -> Result<Vec<String>, SelectorError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spireapi::{MockSpireApiClient, RegistrationEntry, SpireApiError};

    #[tokio::test]
    async fn test_fetch_selectors_returns_selectors_on_success() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .withf(|id| id == "spiffe://example.org/workload")
            .returning(|_| {
                Ok(Some(RegistrationEntry {
                                    spiffe_id: "spiffe://example.org/workload".to_string(),
                                    parent_id: None,
                                    selectors: vec![
                                        "k8s:ns:finance".to_string(),
                                        "k8s:sa:payments-sa".to_string(),
                                    ],
                                }))
            });

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/workload")
            .await
            .unwrap();

        assert_eq!(selectors.len(), 2);
        assert_eq!(selectors[0], "k8s:ns:finance");
        assert_eq!(selectors[1], "k8s:sa:payments-sa");
    }

    #[tokio::test]
    async fn test_fetch_selectors_returns_empty_when_no_entry() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .returning(|_| Ok(None));

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/unknown")
            .await
            .unwrap();

        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_selectors_returns_empty_on_connection_failure() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .returning(|_| Err(SpireApiError::ConnectionFailed("timeout".to_string())));

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/workload")
            .await
            .unwrap();

        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_selectors_returns_empty_on_request_failure() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .returning(|_| Err(SpireApiError::RequestFailed("500".to_string())));

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/workload")
            .await
            .unwrap();

        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_selectors_returns_empty_on_invalid_response() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .returning(|_| Err(SpireApiError::InvalidResponse("bad json".to_string())));

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/workload")
            .await
            .unwrap();

        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_selectors_returns_empty_selectors_list() {
        let mut mock_client = MockSpireApiClient::new();
        mock_client
            .expect_list_entries_by_spiffe_id()
            .returning(|_| {
                Ok(Some(RegistrationEntry {
                                    spiffe_id: "spiffe://example.org/workload".to_string(),
                                    parent_id: None,
                                    selectors: vec![],
                                }))
            });

        let enricher = SpireSelectorEnricher::new(Arc::new(mock_client));
        let selectors = enricher
            .fetch_selectors("spiffe://example.org/workload")
            .await
            .unwrap();

        assert!(selectors.is_empty());
    }
}
