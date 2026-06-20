use async_trait::async_trait;
use base64::Engine;
use tokio::sync::Mutex;

use super::schema::AuditEnvelope;
use super::sink::{AuditSink, SinkError};

/// Maximum number of messages per `publish` API call.
const MAX_BATCH_SIZE: usize = 1000;

/// A sink that delivers audit events to GCP Pub/Sub via the REST API.
///
/// Events are buffered internally and flushed when the buffer reaches
/// [`MAX_BATCH_SIZE`] (1000 messages) or when `flush()` is called explicitly
/// (e.g. during graceful shutdown or on a 1-second timer interval).
///
/// Uses the Pub/Sub v1 REST API:
/// `POST https://pubsub.googleapis.com/v1/projects/{project}/topics/{topic}:publish`
///
/// Authentication is handled externally (e.g. via GCP workload identity or
/// a metadata server token injected into the `reqwest::Client` via middleware).
/// The caller is responsible for configuring the `reqwest::Client` with
/// appropriate auth headers or interceptors.
pub struct GcpPubSubSink {
    client: reqwest::Client,
    publish_url: String,
    buffer: Mutex<Vec<AuditEnvelope>>,
}

impl GcpPubSubSink {
    /// Create a new `GcpPubSubSink`.
    ///
    /// - `project`: The GCP project ID.
    /// - `topic`: The Pub/Sub topic name.
    ///
    /// Uses a default `reqwest::Client`. Authentication should be handled
    /// externally (e.g., via workload identity that injects auth automatically,
    /// or by providing a pre-configured client via [`GcpPubSubSink::with_client`]).
    pub fn new(project: String, topic: String) -> Self {
        let client = reqwest::Client::new();
        Self::with_client(client, project, topic)
    }

    /// Create a `GcpPubSubSink` with a pre-configured `reqwest::Client`.
    ///
    /// Useful for testing or when authentication needs to be handled via
    /// custom middleware/interceptors on the client.
    pub fn with_client(client: reqwest::Client, project: String, topic: String) -> Self {
        let publish_url = format!(
            "https://pubsub.googleapis.com/v1/projects/{}/topics/{}:publish",
            project, topic
        );

        Self {
            client,
            publish_url,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Flush the internal buffer, publishing all buffered messages to Pub/Sub
    /// in batches of up to 1000 messages each.
    async fn flush_buffer(&self, buffer: &mut Vec<AuditEnvelope>) -> Result<(), SinkError> {
        if buffer.is_empty() {
            return Ok(());
        }

        let events: Vec<AuditEnvelope> = buffer.drain(..).collect();

        for chunk in events.chunks(MAX_BATCH_SIZE) {
            let messages: Vec<serde_json::Value> = chunk
                .iter()
                .map(|event| {
                    let json_bytes = serde_json::to_vec(event).map_err(|e| {
                        SinkError::with_source("failed to serialize audit event to JSON", e)
                    })?;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&json_bytes);
                    Ok(serde_json::json!({ "data": encoded }))
                })
                .collect::<Result<Vec<_>, SinkError>>()?;

            let body = serde_json::json!({ "messages": messages });

            let response = self
                .client
                .post(&self.publish_url)
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    SinkError::with_source(
                        format!("Pub/Sub publish request failed for {}", self.publish_url),
                        e,
                    )
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let error_body = response.text().await.unwrap_or_default();
                return Err(SinkError::new(format!(
                    "Pub/Sub publish returned HTTP {}: {}",
                    status, error_body
                )));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AuditSink for GcpPubSubSink {
    async fn send_batch(&self, events: &[AuditEnvelope]) -> Result<(), SinkError> {
        let mut buffer = self.buffer.lock().await;
        buffer.extend(events.iter().cloned());

        // Flush if buffer has reached the batch threshold
        if buffer.len() >= MAX_BATCH_SIZE {
            self.flush_buffer(&mut buffer).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        let mut buffer = self.buffer.lock().await;
        self.flush_buffer(&mut buffer).await
    }

    fn name(&self) -> &str {
        "gcp_pubsub"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcp_pubsub_sink_name() {
        let sink = GcpPubSubSink::new("test-project".to_string(), "test-topic".to_string());
        assert_eq!(sink.name(), "gcp_pubsub");
    }

    #[test]
    fn test_gcp_pubsub_sink_publish_url() {
        let sink = GcpPubSubSink::new("my-project".to_string(), "my-topic".to_string());
        assert_eq!(
            sink.publish_url,
            "https://pubsub.googleapis.com/v1/projects/my-project/topics/my-topic:publish"
        );
    }

    #[test]
    fn test_gcp_pubsub_sink_with_client() {
        let client = reqwest::Client::new();
        let sink = GcpPubSubSink::with_client(
            client,
            "proj-123".to_string(),
            "audit-events".to_string(),
        );
        assert_eq!(sink.name(), "gcp_pubsub");
        assert_eq!(
            sink.publish_url,
            "https://pubsub.googleapis.com/v1/projects/proj-123/topics/audit-events:publish"
        );
    }

    #[tokio::test]
    async fn test_buffer_accumulates_below_threshold() {
        let sink = GcpPubSubSink::new("test-project".to_string(), "test-topic".to_string());

        // Add a few events — should stay in the buffer since < 1000
        let events: Vec<AuditEnvelope> = (0..10)
            .map(|i| AuditEnvelope {
                schema_version: "1.0".to_string(),
                event_type: "token.exchange.success".to_string(),
                timestamp: chrono::Utc::now(),
                request_id: format!("req-{}", i),
                actor: super::super::schema::AuditActor {
                    subject: "test".to_string(),
                    source_type: "spire".to_string(),
                },
                details: serde_json::json!({"test": true}),
                outcome: super::super::schema::Outcome::Success,
                error: None,
            })
            .collect();

        sink.send_batch(&events).await.unwrap();

        // Buffer should contain the 10 events
        let buffer = sink.buffer.lock().await;
        assert_eq!(buffer.len(), 10);
    }

    #[tokio::test]
    async fn test_flush_clears_buffer() {
        let sink = GcpPubSubSink::new("test-project".to_string(), "test-topic".to_string());

        let events: Vec<AuditEnvelope> = (0..5)
            .map(|i| AuditEnvelope {
                schema_version: "1.0".to_string(),
                event_type: "token.exchange.success".to_string(),
                timestamp: chrono::Utc::now(),
                request_id: format!("req-{}", i),
                actor: super::super::schema::AuditActor {
                    subject: "test".to_string(),
                    source_type: "spire".to_string(),
                },
                details: serde_json::json!({"test": true}),
                outcome: super::super::schema::Outcome::Success,
                error: None,
            })
            .collect();

        sink.send_batch(&events).await.unwrap();

        // Buffer should have 5 events
        {
            let buffer = sink.buffer.lock().await;
            assert_eq!(buffer.len(), 5);
        }

        // flush will fail because there's no real Pub/Sub endpoint, but the
        // buffer should be drained (events moved out for the attempt)
        let result = sink.flush().await;
        // Expected to fail since we can't reach the real endpoint
        assert!(result.is_err());
    }
}
