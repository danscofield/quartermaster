// Selector enricher trait for SPIRE identity processing.
//
// This trait abstracts selector retrieval during identity authentication.
// When path patterns are configured, the NoOpSelectorEnricher is used (no API calls).
// When server_addr is configured without path patterns, a SPIRE API-backed enricher is used.

/// Trait for enriching SPIRE identities with selector information.
#[async_trait::async_trait]
pub trait SelectorEnricher: Send + Sync {
    /// Returns selectors for the given SPIFFE ID.
    async fn get_selectors(&self, spiffe_id: &str) -> Vec<String>;
}

/// No-op enricher that returns no selectors.
/// Used when path patterns are configured or when no server_addr is set.
pub struct NoOpSelectorEnricher;

#[async_trait::async_trait]
impl SelectorEnricher for NoOpSelectorEnricher {
    async fn get_selectors(&self, _spiffe_id: &str) -> Vec<String> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_selector_enricher_returns_empty_vec() {
        let enricher = NoOpSelectorEnricher;
        let selectors = enricher.get_selectors("spiffe://example.com/ns/default/sa/api").await;
        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_noop_selector_enricher_returns_empty_for_any_input() {
        let enricher = NoOpSelectorEnricher;

        let selectors = enricher.get_selectors("").await;
        assert!(selectors.is_empty());

        let selectors = enricher.get_selectors("spiffe://trust.domain/long/path/with/many/segments").await;
        assert!(selectors.is_empty());

        let selectors = enricher.get_selectors("not-a-spiffe-id").await;
        assert!(selectors.is_empty());
    }

    #[tokio::test]
    async fn test_noop_selector_enricher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpSelectorEnricher>();
    }

    #[tokio::test]
    async fn test_trait_object_usage() {
        let enricher: Box<dyn SelectorEnricher> = Box::new(NoOpSelectorEnricher);
        let selectors = enricher.get_selectors("spiffe://example.com/workload").await;
        assert!(selectors.is_empty());
    }
}
