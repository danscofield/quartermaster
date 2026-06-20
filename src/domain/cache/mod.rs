pub mod memory;
pub mod redis;

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
///
/// The cache key is `subject + audience`, where `subject` is the formatted `sub` claim
/// for the authenticated identity. This generalizes across all identity sources:
/// - SPIRE: the literal SPIFFE ID (e.g., `spiffe://example.com/workload`)
/// - OIDC: `human:<email>` (e.g., `human:alice@corp.example.com`)
/// - AWS STS: `aws:<account_id>:<role_name>` (e.g., `aws:123456789012:billing-service`)
/// - GCP: `gcp:<project_id>:<email>` (e.g., `gcp:my-project:sa@proj.iam.gserviceaccount.com`)
#[async_trait::async_trait]
pub trait Cache: Send + Sync {
    /// Get retrieves a cached entry by subject and audience. Returns None if not found or expired.
    async fn get(&self, subject: &str, audience: &str) -> Result<Option<CacheEntry>, CacheError>;

    /// Set stores a billet resolution result with the given TTL.
    /// The `subject` is the formatted sub claim (see trait-level docs for format per source type).
    async fn set(
        &self,
        subject: &str,
        audience: &str,
        billets: Vec<String>,
        ttl: Duration,
    ) -> Result<(), CacheError>;

    /// Delete removes a cached entry by subject and audience.
    async fn delete(&self, subject: &str, audience: &str) -> Result<(), CacheError>;
}
