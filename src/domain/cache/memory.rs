use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tokio::time::Instant;

use super::{Cache, CacheEntry, CacheError};

/// Internal storage entry that includes TTL information for expiry checking.
///
/// Uses `tokio::time::Instant` for expiry tracking so that expiration is
/// monotonic and compatible with `tokio::time::pause()` in tests.
/// The `stored_at` chrono timestamp is kept for the public `CacheEntry`.
#[derive(Debug, Clone)]
struct InternalEntry {
    billets: Vec<String>,
    stored_at: DateTime<Utc>,
    expires_at: Instant,
}

impl InternalEntry {
    /// Returns true if this entry has expired.
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// An in-memory cache implementation using `tokio::sync::RwLock<HashMap>`.
///
/// Expiry is enforced lazily on `get` (expired entries are removed when accessed)
/// and optionally via a background cleanup task spawned at construction time.
#[derive(Clone)]
pub struct InMemoryCache {
    store: Arc<RwLock<HashMap<String, InternalEntry>>>,
}

impl InMemoryCache {
    /// Creates a new empty InMemoryCache.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a new InMemoryCache and spawns a background task that periodically
    /// removes expired entries.
    ///
    /// The cleanup task runs every `cleanup_interval` and removes all entries
    /// whose TTL has elapsed.
    pub fn with_background_cleanup(cleanup_interval: Duration) -> Self {
        let cache = Self::new();
        let store = Arc::clone(&cache.store);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let mut map = store.write().await;
                map.retain(|_, entry| !entry.is_expired());
            }
        });

        cache
    }

    /// Constructs the cache key from spiffe_id and audience.
    fn cache_key(spiffe_id: &str, audience: &str) -> String {
        format!("{}:{}", spiffe_id, audience)
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Cache for InMemoryCache {
    async fn get(&self, spiffe_id: &str, audience: &str) -> Result<Option<CacheEntry>, CacheError> {
        let key = Self::cache_key(spiffe_id, audience);

        // First try with a read lock for the common case (entry exists and is valid)
        {
            let map = self.store.read().await;
            if let Some(entry) = map.get(&key) {
                if !entry.is_expired() {
                    return Ok(Some(CacheEntry {
                        billets: entry.billets.clone(),
                        stored_at: entry.stored_at,
                    }));
                }
            } else {
                return Ok(None);
            }
        }

        // Entry exists but is expired — acquire write lock to remove it (lazy cleanup)
        let mut map = self.store.write().await;
        // Re-check in case another task already removed/updated it
        if let Some(entry) = map.get(&key) {
            if entry.is_expired() {
                map.remove(&key);
            } else {
                // Another task updated it with a fresh entry
                return Ok(Some(CacheEntry {
                    billets: entry.billets.clone(),
                    stored_at: entry.stored_at,
                }));
            }
        }

        Ok(None)
    }

    async fn set(
        &self,
        spiffe_id: &str,
        audience: &str,
        billets: Vec<String>,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let key = Self::cache_key(spiffe_id, audience);
        let entry = InternalEntry {
            billets,
            stored_at: Utc::now(),
            expires_at: Instant::now() + ttl,
        };

        let mut map = self.store.write().await;
        map.insert(key, entry);
        Ok(())
    }

    async fn delete(&self, spiffe_id: &str, audience: &str) -> Result<(), CacheError> {
        let key = Self::cache_key(spiffe_id, audience);
        let mut map = self.store.write().await;
        map.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get() {
        let cache = InMemoryCache::new();
        let billets = vec!["billet-a".to_string(), "billet-b".to_string()];

        cache
            .set("spiffe://example/workload", "api.example.com", billets.clone(), Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache
            .get("spiffe://example/workload", "api.example.com")
            .await
            .unwrap();

        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.billets, billets);
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_none() {
        let cache = InMemoryCache::new();

        let result = cache
            .get("spiffe://example/unknown", "audience")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_removes_entry() {
        let cache = InMemoryCache::new();
        let billets = vec!["billet-x".to_string()];

        cache
            .set("spiffe://example/w", "aud", billets, Duration::from_secs(60))
            .await
            .unwrap();

        cache.delete("spiffe://example/w", "aud").await.unwrap();

        let result = cache.get("spiffe://example/w", "aud").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_expired_entry_returns_none() {
        // Use tokio's time control to test expiry
        tokio::time::pause();

        let cache = InMemoryCache::new();
        let billets = vec!["billet-expired".to_string()];

        cache
            .set("spiffe://example/exp", "aud", billets, Duration::from_secs(10))
            .await
            .unwrap();

        // Entry should be present immediately
        let result = cache.get("spiffe://example/exp", "aud").await.unwrap();
        assert!(result.is_some());

        // Advance time past TTL
        tokio::time::advance(Duration::from_secs(11)).await;

        // Entry should now be expired
        let result = cache.get("spiffe://example/exp", "aud").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_set_overwrites_existing_entry() {
        let cache = InMemoryCache::new();

        cache
            .set("spiffe://example/w", "aud", vec!["old".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        cache
            .set("spiffe://example/w", "aud", vec!["new".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("spiffe://example/w", "aud").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().billets, vec!["new".to_string()]);
    }

    #[tokio::test]
    async fn test_different_keys_are_independent() {
        let cache = InMemoryCache::new();

        cache
            .set("spiffe://example/a", "aud1", vec!["a".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        cache
            .set("spiffe://example/b", "aud2", vec!["b".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        let result_a = cache.get("spiffe://example/a", "aud1").await.unwrap();
        let result_b = cache.get("spiffe://example/b", "aud2").await.unwrap();

        assert_eq!(result_a.unwrap().billets, vec!["a".to_string()]);
        assert_eq!(result_b.unwrap().billets, vec!["b".to_string()]);
    }

    #[tokio::test]
    async fn test_same_spiffe_id_different_audience() {
        let cache = InMemoryCache::new();

        cache
            .set("spiffe://example/w", "aud1", vec!["x".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        cache
            .set("spiffe://example/w", "aud2", vec!["y".to_string()], Duration::from_secs(60))
            .await
            .unwrap();

        let result1 = cache.get("spiffe://example/w", "aud1").await.unwrap();
        let result2 = cache.get("spiffe://example/w", "aud2").await.unwrap();

        assert_eq!(result1.unwrap().billets, vec!["x".to_string()]);
        assert_eq!(result2.unwrap().billets, vec!["y".to_string()]);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_is_noop() {
        let cache = InMemoryCache::new();
        // Should not panic or error
        cache.delete("spiffe://example/none", "aud").await.unwrap();
    }
}
