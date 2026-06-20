pub mod memory;

use std::time::Duration;

/// Entry represents a cached billet resolution result.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub billets: Vec<String>,
    pub stored_at: chrono::DateTime<chrono::Utc>,
}

/// Errors that can occur during cache operations.
#[derive(Debug, Clone)]
pub enum CacheError {
    /// An error from the underlying storage backend.
    BackendError(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::BackendError(msg) => write!(f, "cache backend error: {}", msg),
        }
    }
}

impl std::error::Error for CacheError {}

/// Cache defines the abstract interface for billet resolution caching.
/// Implementations must be safe for concurrent use (Send + Sync).
#[async_trait::async_trait]
pub trait Cache: Send + Sync {
    /// Get retrieves a cached entry. Returns None if not found or expired.
    async fn get(&self, spiffe_id: &str, audience: &str) -> Result<Option<CacheEntry>, CacheError>;

    /// Set stores a billet resolution result with the given TTL.
    async fn set(
        &self,
        spiffe_id: &str,
        audience: &str,
        billets: Vec<String>,
        ttl: Duration,
    ) -> Result<(), CacheError>;

    /// Delete removes a cached entry.
    async fn delete(&self, spiffe_id: &str, audience: &str) -> Result<(), CacheError>;
}
