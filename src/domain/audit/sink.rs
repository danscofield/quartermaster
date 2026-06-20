use std::fmt;

use async_trait::async_trait;

use super::schema::AuditEnvelope;

/// Error type for audit sink failures.
///
/// Wraps an underlying error with the sink name for diagnostic context.
#[derive(Debug)]
pub struct SinkError {
    /// Human-readable description of what went wrong.
    pub message: String,
    /// Optional underlying cause.
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SinkError {
    /// Create a new `SinkError` with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new `SinkError` wrapping an underlying error.
    pub fn with_source(message: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(ref source) = self.source {
            write!(f, ": {}", source)?;
        }
        Ok(())
    }
}

impl std::error::Error for SinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Trait for pluggable audit event sinks.
///
/// Implementations deliver audit events to various backends (stdout, file,
/// Kinesis Firehose, GCP Pub/Sub, etc.). The `AuditService` fans out events
/// to all configured sinks sequentially.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Deliver a batch of serialized audit events.
    /// Sinks that don't support batching can iterate and send individually.
    async fn send_batch(&self, events: &[AuditEnvelope]) -> Result<(), SinkError>;

    /// Flush any internally buffered events (called on graceful shutdown).
    async fn flush(&self) -> Result<(), SinkError>;

    /// Human-readable sink name (for diagnostics).
    fn name(&self) -> &str;
}
