use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::Instant;

/// Errors that can occur during rate limiting operations.
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// An error from the underlying storage backend.
    BackendError(String),
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::BackendError(msg) => write!(f, "rate limit backend error: {}", msg),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Limiter enforces per-subject request rate limits.
///
/// The subject is the source-specific identifier (e.g., the SPIFFE ID for SPIRE,
/// `human:<email>` for OIDC, `aws:<account_id>:<role_name>` for AWS STS, etc.).
#[async_trait::async_trait]
pub trait Limiter: Send + Sync {
    /// Checks if a request from the given subject is within rate limits.
    /// Returns true if allowed, false if rate limited.
    ///
    /// The `subject` parameter is the formatted subject string for the identity source
    /// (for SPIRE this is the SPIFFE ID, for other sources it follows the format defined
    /// by `format_subject`).
    async fn allow(&self, subject: &str) -> Result<bool, RateLimitError>;
}

/// An in-memory rate limiter using a sliding window approach.
///
/// For each subject, tracks timestamps of requests within the configured window
/// (default 60 seconds). A request is allowed if the number of requests in the
/// current window is below the configured limit.
///
/// Stale entries are cleaned up periodically via a background task.
#[derive(Clone)]
pub struct InMemoryLimiter {
    /// Per-subject request timestamps within the sliding window.
    windows: Arc<RwLock<HashMap<String, VecDeque<Instant>>>>,
    /// Maximum number of requests allowed per window.
    requests_per_minute: u32,
    /// The duration of the sliding window.
    window_duration: Duration,
}

impl InMemoryLimiter {
    /// Creates a new InMemoryLimiter with the specified requests per minute limit.
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            requests_per_minute,
            window_duration: Duration::from_secs(60),
        }
    }

    /// Creates a new InMemoryLimiter and spawns a background task that periodically
    /// cleans up stale entries (subjects with no recent requests).
    ///
    /// The cleanup task runs every `cleanup_interval` and removes entries that have
    /// no timestamps within the current window.
    pub fn with_background_cleanup(requests_per_minute: u32, cleanup_interval: Duration) -> Self {
        let limiter = Self::new(requests_per_minute);
        let windows = Arc::clone(&limiter.windows);
        let window_duration = limiter.window_duration;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let cutoff = now - window_duration;
                let mut map = windows.write().await;

                // For each subject, remove timestamps older than the window
                map.retain(|_, timestamps| {
                    // Remove expired timestamps from the front
                    while let Some(&front) = timestamps.front() {
                        if front < cutoff {
                            timestamps.pop_front();
                        } else {
                            break;
                        }
                    }
                    // Remove the entry entirely if no timestamps remain
                    !timestamps.is_empty()
                });
            }
        });

        limiter
    }
}

#[async_trait::async_trait]
impl Limiter for InMemoryLimiter {
    async fn allow(&self, subject: &str) -> Result<bool, RateLimitError> {
        let now = Instant::now();
        let cutoff = now - self.window_duration;

        let mut map = self.windows.write().await;
        let timestamps = map.entry(subject.to_string()).or_insert_with(VecDeque::new);

        // Remove timestamps older than the sliding window
        while let Some(&front) = timestamps.front() {
            if front < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check if under the limit
        if (timestamps.len() as u32) < self.requests_per_minute {
            timestamps.push_back(now);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allows_requests_under_limit() {
        let limiter = InMemoryLimiter::new(5);

        for _ in 0..5 {
            let result = limiter.allow("spiffe://example/workload").await.unwrap();
            assert!(result);
        }
    }

    #[tokio::test]
    async fn test_rejects_requests_over_limit() {
        let limiter = InMemoryLimiter::new(3);

        // First 3 should be allowed
        for _ in 0..3 {
            let result = limiter.allow("spiffe://example/workload").await.unwrap();
            assert!(result);
        }

        // 4th should be rejected
        let result = limiter.allow("spiffe://example/workload").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_different_subjects_are_independent() {
        let limiter = InMemoryLimiter::new(2);

        // Fill up subject A
        assert!(limiter.allow("spiffe://example/a").await.unwrap());
        assert!(limiter.allow("spiffe://example/a").await.unwrap());
        assert!(!limiter.allow("spiffe://example/a").await.unwrap());

        // Subject B should still be allowed
        assert!(limiter.allow("spiffe://example/b").await.unwrap());
        assert!(limiter.allow("spiffe://example/b").await.unwrap());
        assert!(!limiter.allow("spiffe://example/b").await.unwrap());
    }

    #[tokio::test]
    async fn test_window_expires_and_allows_again() {
        tokio::time::pause();

        let limiter = InMemoryLimiter::new(2);

        // Use up the limit
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(!limiter.allow("spiffe://example/w").await.unwrap());

        // Advance time past the window (60 seconds)
        tokio::time::advance(Duration::from_secs(61)).await;

        // Should be allowed again
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(!limiter.allow("spiffe://example/w").await.unwrap());
    }

    #[tokio::test]
    async fn test_sliding_window_partial_expiry() {
        tokio::time::pause();

        let limiter = InMemoryLimiter::new(3);

        // Make 2 requests at t=0
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(limiter.allow("spiffe://example/w").await.unwrap());

        // Advance 30 seconds and make 1 more request
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(limiter.allow("spiffe://example/w").await.unwrap());

        // Now at limit (3 requests in the window)
        assert!(!limiter.allow("spiffe://example/w").await.unwrap());

        // Advance 31 more seconds (total 61 from first requests)
        // The first 2 requests should have expired
        tokio::time::advance(Duration::from_secs(31)).await;

        // Should allow 2 more (only the request at t=30 is still in the window)
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(limiter.allow("spiffe://example/w").await.unwrap());
        assert!(!limiter.allow("spiffe://example/w").await.unwrap());
    }

    #[tokio::test]
    async fn test_limit_of_one() {
        let limiter = InMemoryLimiter::new(1);

        assert!(limiter.allow("spiffe://example/single").await.unwrap());
        assert!(!limiter.allow("spiffe://example/single").await.unwrap());
    }

    #[tokio::test]
    async fn test_background_cleanup_removes_stale_entries() {
        tokio::time::pause();

        let limiter = InMemoryLimiter::with_background_cleanup(2, Duration::from_secs(10));

        // Make a request
        assert!(limiter.allow("spiffe://example/cleanup").await.unwrap());

        // Verify entry exists
        {
            let map = limiter.windows.read().await;
            assert!(map.contains_key("spiffe://example/cleanup"));
        }

        // Advance past window + cleanup interval
        tokio::time::advance(Duration::from_secs(71)).await;

        // Give the cleanup task a chance to run
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        // Entry should be cleaned up
        {
            let map = limiter.windows.read().await;
            assert!(!map.contains_key("spiffe://example/cleanup"));
        }
    }
}
