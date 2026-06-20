use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::schema::AuditEnvelope;
use super::sink::{AuditSink, SinkError};

/// A sink that writes JSON-serialized audit events to stdout, one per line.
///
/// Each event is serialized immediately on `send_batch` with no internal
/// buffering. `flush` is a no-op since stdout is unbuffered.
pub struct StdoutSink;

impl StdoutSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for StdoutSink {
    async fn send_batch(&self, events: &[AuditEnvelope]) -> Result<(), SinkError> {
        let mut stdout = tokio::io::stdout();
        for event in events {
            let json = serde_json::to_string(event).map_err(|e| {
                SinkError::with_source("failed to serialize audit event", e)
            })?;
            let mut line = json.into_bytes();
            line.push(b'\n');
            stdout.write_all(&line).await.map_err(|e| {
                SinkError::with_source("failed to write to stdout", e)
            })?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        // No-op: stdout is unbuffered
        Ok(())
    }

    fn name(&self) -> &str {
        "stdout"
    }
}
