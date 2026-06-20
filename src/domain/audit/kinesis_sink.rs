use async_trait::async_trait;
use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::Record;
use aws_sdk_firehose::Client;
use tokio::sync::Mutex;

use super::schema::AuditEnvelope;
use super::sink::{AuditSink, SinkError};

/// Maximum number of records per `PutRecordBatch` API call.
const MAX_BATCH_SIZE: usize = 500;

/// A sink that delivers audit events to AWS Kinesis Data Firehose.
///
/// Events are buffered internally and flushed when the buffer reaches
/// [`MAX_BATCH_SIZE`] (500 records) or when `flush()` is called explicitly
/// (e.g. during graceful shutdown).
///
/// Uses the `PutRecordBatch` API which supports up to 500 records per call.
pub struct KinesisFirehoseSink {
    client: Client,
    stream_name: String,
    buffer: Mutex<Vec<AuditEnvelope>>,
}

impl KinesisFirehoseSink {
    /// Create a new `KinesisFirehoseSink`.
    ///
    /// - `stream_name`: The name of the Firehose delivery stream.
    /// - `region`: The AWS region where the delivery stream is located.
    pub async fn new(stream_name: String, region: String) -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_firehose::config::Region::new(region))
            .load()
            .await;

        let client = Client::new(&config);

        Self {
            client,
            stream_name,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Create a `KinesisFirehoseSink` with a pre-configured client.
    ///
    /// Useful for testing with mock or custom-configured clients.
    pub fn with_client(client: Client, stream_name: String) -> Self {
        Self {
            client,
            stream_name,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Flush the internal buffer, sending all buffered records to Firehose
    /// in batches of up to 500 records each.
    async fn flush_buffer(&self, buffer: &mut Vec<AuditEnvelope>) -> Result<(), SinkError> {
        if buffer.is_empty() {
            return Ok(());
        }

        // Drain the buffer and send in chunks of MAX_BATCH_SIZE
        let events: Vec<AuditEnvelope> = buffer.drain(..).collect();

        for chunk in events.chunks(MAX_BATCH_SIZE) {
            let records: Vec<Record> = chunk
                .iter()
                .map(|event| {
                    let json = serde_json::to_vec(event).map_err(|e| {
                        SinkError::with_source("failed to serialize audit event to JSON", e)
                    });
                    json.map(|data| {
                        Record::builder()
                            .data(Blob::new(data))
                            .build()
                            .expect("Record builder should not fail with data set")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            self.client
                .put_record_batch()
                .delivery_stream_name(&self.stream_name)
                .set_records(Some(records))
                .send()
                .await
                .map_err(|e| {
                    SinkError::with_source(
                        format!(
                            "PutRecordBatch failed for stream '{}'",
                            self.stream_name
                        ),
                        e,
                    )
                })?;
        }

        Ok(())
    }
}

#[async_trait]
impl AuditSink for KinesisFirehoseSink {
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
        "kinesis_firehose"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kinesis_firehose_sink_name() {
        // Verify the sink reports its name correctly.
        // We use with_client to avoid needing real AWS credentials.
        let config = aws_sdk_firehose::Config::builder()
            .behavior_version_latest()
            .build();
        let client = Client::from_conf(config);

        let sink = KinesisFirehoseSink::with_client(
            client,
            "test-stream".to_string(),
        );

        assert_eq!(sink.name(), "kinesis_firehose");
    }

    #[tokio::test]
    async fn test_buffer_accumulates_below_threshold() {
        let config = aws_sdk_firehose::Config::builder()
            .behavior_version_latest()
            .build();
        let client = Client::from_conf(config);

        let sink = KinesisFirehoseSink::with_client(
            client,
            "test-stream".to_string(),
        );

        // Add a few events — should stay in the buffer since < 500
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
}
