use std::time::Duration;

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use super::{Cache, CacheEntry, CacheError};

/// JSON-serializable representation of a cache entry stored in Redis.
#[derive(Debug, Serialize, Deserialize)]
struct StoredEntry {
    billets: Vec<String>,
    stored_at: DateTime<Utc>,
}

/// A Redis-backed cache implementation using `redis::aio::ConnectionManager`.
///
/// The connection manager automatically handles reconnections, making this
/// suitable for long-running server processes.
///
/// Keys are stored with format `qm:cache:{subject}:{audience}` and values
/// are JSON-serialized `StoredEntry` structs. TTL is enforced via Redis
/// native key expiration (SETEX).
#[derive(Clone)]
pub struct RedisCache {
    connection_manager: redis::aio::ConnectionManager,
}

impl RedisCache {
    /// Creates a new RedisCache connected to the given Redis URL.
    ///
    /// The URL should be in the format `redis://host:port` or
    /// `redis://user:password@host:port/db`.
    ///
    /// Returns `CacheError::BackendError` if the connection cannot be established.
    pub async fn new(url: &str) -> Result<Self, CacheError> {
        let client = redis::Client::open(url)
            .map_err(|e| CacheError::BackendError(format!("failed to create Redis client: {}", e)))?;

        let connection_manager = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| CacheError::BackendError(format!("failed to connect to Redis: {}", e)))?;

        Ok(Self { connection_manager })
    }

    /// Constructs the Redis key from subject and audience.
    fn cache_key(subject: &str, audience: &str) -> String {
        format!("qm:cache:{}:{}", subject, audience)
    }
}

#[async_trait::async_trait]
impl Cache for RedisCache {
    async fn get(&self, subject: &str, audience: &str) -> Result<Option<CacheEntry>, CacheError> {
        let key = Self::cache_key(subject, audience);
        let mut conn = self.connection_manager.clone();

        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| CacheError::BackendError(format!("Redis GET failed: {}", e)))?;

        match value {
            None => Ok(None),
            Some(json) => {
                let stored: StoredEntry = serde_json::from_str(&json)
                    .map_err(|e| CacheError::BackendError(format!("failed to deserialize cache entry: {}", e)))?;

                Ok(Some(CacheEntry {
                    billets: stored.billets,
                    stored_at: stored.stored_at,
                }))
            }
        }
    }

    async fn set(
        &self,
        subject: &str,
        audience: &str,
        billets: Vec<String>,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let key = Self::cache_key(subject, audience);
        let mut conn = self.connection_manager.clone();

        let stored = StoredEntry {
            billets,
            stored_at: Utc::now(),
        };

        let json = serde_json::to_string(&stored)
            .map_err(|e| CacheError::BackendError(format!("failed to serialize cache entry: {}", e)))?;

        let ttl_secs = ttl.as_secs().max(1);

        conn.set_ex::<_, _, ()>(&key, &json, ttl_secs)
            .await
            .map_err(|e| CacheError::BackendError(format!("Redis SETEX failed: {}", e)))?;

        Ok(())
    }

    async fn delete(&self, subject: &str, audience: &str) -> Result<(), CacheError> {
        let key = Self::cache_key(subject, audience);
        let mut conn = self.connection_manager.clone();

        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| CacheError::BackendError(format!("Redis DEL failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        let key = RedisCache::cache_key("spiffe://example.com/workload", "api.example.com");
        assert_eq!(key, "qm:cache:spiffe://example.com/workload:api.example.com");
    }

    #[test]
    fn test_cache_key_with_special_characters() {
        let key = RedisCache::cache_key("human:alice@corp.example.com", "my-service");
        assert_eq!(key, "qm:cache:human:alice@corp.example.com:my-service");
    }

    #[test]
    fn test_stored_entry_serialization() {
        let entry = StoredEntry {
            billets: vec!["billing".to_string(), "analytics".to_string()],
            stored_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: StoredEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.billets, entry.billets);
        assert_eq!(deserialized.stored_at, entry.stored_at);
    }

    #[test]
    fn test_stored_entry_deserialization_from_expected_format() {
        let json = r#"{"billets":["billing","analytics"],"stored_at":"2024-01-15T10:30:00Z"}"#;
        let entry: StoredEntry = serde_json::from_str(json).unwrap();

        assert_eq!(entry.billets, vec!["billing", "analytics"]);
        assert_eq!(
            entry.stored_at,
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }
}
