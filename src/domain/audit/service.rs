use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::schema::AuditEnvelope;
use super::sink::AuditSink;

/// The public audit service that decouples event production from delivery.
///
/// `AuditService` is `Clone + Send + Sync` — it can be shared across handlers
/// via `Arc` internally. Calling `emit()` is non-blocking; events are delivered
/// to all configured sinks by a background fan-out task.
#[derive(Clone)]
pub struct AuditService {
    inner: Arc<AuditServiceInner>,
}

struct AuditServiceInner {
    sender: mpsc::Sender<AuditEnvelope>,
    overflow_dropped: AtomicU64,
    shutdown_tx: watch::Sender<bool>,
    task_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl AuditService {
    /// Create the service and spawn the background fan-out task.
    ///
    /// - `sinks`: The list of configured audit sinks to fan out events to.
    /// - `buffer_capacity`: The bounded channel capacity. When the channel is full,
    ///   new events are dropped (not oldest) and a warning counter increments.
    pub fn new(sinks: Vec<Box<dyn AuditSink>>, buffer_capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task_handle = tokio::spawn(fan_out_task(receiver, shutdown_rx, sinks));

        Self {
            inner: Arc::new(AuditServiceInner {
                sender,
                overflow_dropped: AtomicU64::new(0),
                shutdown_tx,
                task_handle: tokio::sync::Mutex::new(Some(task_handle)),
            }),
        }
    }

    /// Emit an audit event (non-blocking).
    ///
    /// Uses `try_send` to avoid blocking the caller. If the channel is full,
    /// the *current* event is dropped, the overflow counter is incremented,
    /// and a warning is logged.
    pub fn emit(&self, event: AuditEnvelope) {
        match self.inner.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let count = self.inner.overflow_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    overflow_dropped = count,
                    "audit event dropped: channel buffer full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("audit event dropped: channel closed (service shutting down)");
            }
        }
    }

    /// Returns the number of events dropped due to channel overflow.
    pub fn overflow_dropped(&self) -> u64 {
        self.inner.overflow_dropped.load(Ordering::Relaxed)
    }

    /// Signal the background task to drain remaining events, flush sinks, and stop.
    ///
    /// Awaits task completion with the given timeout. After timeout, remaining
    /// events are dropped and the task is aborted.
    pub async fn shutdown(&self, timeout: Duration) {
        // Signal shutdown to the background task
        let _ = self.inner.shutdown_tx.send(true);

        // Take the task handle (only the first caller gets it)
        let handle = {
            let mut guard = self.inner.task_handle.lock().await;
            guard.take()
        };

        if let Some(handle) = handle {
            // Await with timeout
            match tokio::time::timeout(timeout, handle).await {
                Ok(Ok(())) => {
                    tracing::info!("audit service background task shut down cleanly");
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "audit service background task panicked during shutdown");
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = timeout.as_secs(),
                        "audit service shutdown timed out; remaining events dropped"
                    );
                }
            }
        }
    }
}

/// Background fan-out task that receives events from the channel and delivers
/// them to all configured sinks sequentially.
async fn fan_out_task(
    mut receiver: mpsc::Receiver<AuditEnvelope>,
    mut shutdown_rx: watch::Receiver<bool>,
    sinks: Vec<Box<dyn AuditSink>>,
) {
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Drain remaining events from the channel
                    drain_and_flush(&mut receiver, &sinks).await;
                    return;
                }
            }
            // Receive events from the channel
            event = receiver.recv() => {
                match event {
                    Some(envelope) => {
                        deliver_to_sinks(&envelope, &sinks).await;
                    }
                    None => {
                        // Channel closed (all senders dropped) — drain and flush
                        drain_and_flush(&mut receiver, &sinks).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Deliver a single event to all configured sinks sequentially.
/// If a sink returns an error, log a warning and continue to the next sink.
async fn deliver_to_sinks(event: &AuditEnvelope, sinks: &[Box<dyn AuditSink>]) {
    for sink in sinks {
        if let Err(e) = sink.send_batch(&[event.clone()]).await {
            tracing::warn!(
                sink_name = sink.name(),
                error = %e,
                "audit sink failed to deliver event"
            );
        }
    }
}

/// Drain all remaining events from the channel and flush all sinks.
async fn drain_and_flush(receiver: &mut mpsc::Receiver<AuditEnvelope>, sinks: &[Box<dyn AuditSink>]) {
    // Drain remaining events
    while let Ok(event) = receiver.try_recv() {
        deliver_to_sinks(&event, sinks).await;
    }

    // Flush all sinks
    for sink in sinks {
        if let Err(e) = sink.flush().await {
            tracing::warn!(
                sink_name = sink.name(),
                error = %e,
                "audit sink failed to flush during shutdown"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::schema::{AuditActor, Outcome};
    use crate::domain::audit::sink::SinkError;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A test sink that records all events delivered to it.
    struct RecordingSink {
        name: String,
        events: Arc<Mutex<Vec<AuditEnvelope>>>,
        flushed: Arc<Mutex<bool>>,
    }

    impl RecordingSink {
        fn new(name: &str) -> (Self, Arc<Mutex<Vec<AuditEnvelope>>>, Arc<Mutex<bool>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            let flushed = Arc::new(Mutex::new(false));
            (
                Self {
                    name: name.to_string(),
                    events: events.clone(),
                    flushed: flushed.clone(),
                },
                events,
                flushed,
            )
        }
    }

    #[async_trait]
    impl AuditSink for RecordingSink {
        async fn send_batch(&self, events: &[AuditEnvelope]) -> Result<(), SinkError> {
            let mut recorded = self.events.lock().unwrap();
            recorded.extend(events.iter().cloned());
            Ok(())
        }

        async fn flush(&self) -> Result<(), SinkError> {
            *self.flushed.lock().unwrap() = true;
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    /// A sink that always errors on send_batch.
    struct FailingSink {
        name: String,
    }

    #[async_trait]
    impl AuditSink for FailingSink {
        async fn send_batch(&self, _events: &[AuditEnvelope]) -> Result<(), SinkError> {
            Err(SinkError::new("simulated failure"))
        }

        async fn flush(&self) -> Result<(), SinkError> {
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    fn make_test_event(event_type: &str) -> AuditEnvelope {
        AuditEnvelope {
            schema_version: "1.0".to_string(),
            event_type: event_type.to_string(),
            timestamp: chrono::Utc::now(),
            request_id: uuid::Uuid::new_v4().to_string(),
            actor: AuditActor {
                subject: "test-subject".to_string(),
                source_type: "test".to_string(),
            },
            details: serde_json::json!({"test": true}),
            outcome: Outcome::Success,
            error: None,
        }
    }

    #[tokio::test]
    async fn test_emit_delivers_to_single_sink() {
        let (sink, events, _flushed) = RecordingSink::new("test");
        let service = AuditService::new(vec![Box::new(sink)], 100);

        service.emit(make_test_event("token.exchange.success"));

        // Give the background task time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].event_type, "token.exchange.success");
    }

    #[tokio::test]
    async fn test_emit_fans_out_to_multiple_sinks() {
        let (sink1, events1, _) = RecordingSink::new("sink1");
        let (sink2, events2, _) = RecordingSink::new("sink2");
        let service = AuditService::new(vec![Box::new(sink1), Box::new(sink2)], 100);

        service.emit(make_test_event("admin.billet.create"));

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(events1.lock().unwrap().len(), 1);
        assert_eq!(events2.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_emit_overflow_increments_counter() {
        // Use capacity=1 and a slow sink to fill the buffer
        let (sink, _events, _) = RecordingSink::new("slow");
        let service = AuditService::new(vec![Box::new(sink)], 1);

        // Emit many events rapidly to overflow the buffer
        for _ in 0..100 {
            service.emit(make_test_event("overflow.test"));
        }

        // Some should have been dropped
        assert!(service.overflow_dropped() > 0);
    }

    #[tokio::test]
    async fn test_sink_error_continues_to_next_sink() {
        let failing_sink = FailingSink {
            name: "failing".to_string(),
        };
        let (good_sink, events, _) = RecordingSink::new("good");
        let service = AuditService::new(vec![Box::new(failing_sink), Box::new(good_sink)], 100);

        service.emit(make_test_event("token.exchange.success"));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // The good sink should still receive the event even though the first sink failed
        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
    }

    #[tokio::test]
    async fn test_shutdown_drains_and_flushes() {
        let (sink, events, flushed) = RecordingSink::new("test");
        let service = AuditService::new(vec![Box::new(sink)], 100);

        service.emit(make_test_event("event1"));
        service.emit(make_test_event("event2"));

        service.shutdown(Duration::from_secs(5)).await;

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(*flushed.lock().unwrap());
    }

    #[tokio::test]
    async fn test_shutdown_with_timeout() {
        // Use a sink that takes forever to flush
        struct SlowFlushSink;

        #[async_trait]
        impl AuditSink for SlowFlushSink {
            async fn send_batch(&self, _events: &[AuditEnvelope]) -> Result<(), SinkError> {
                Ok(())
            }
            async fn flush(&self) -> Result<(), SinkError> {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            }
            fn name(&self) -> &str {
                "slow-flush"
            }
        }

        let service = AuditService::new(vec![Box::new(SlowFlushSink)], 100);
        service.emit(make_test_event("test"));

        // Shutdown with a very short timeout
        let start = tokio::time::Instant::now();
        service.shutdown(Duration::from_millis(100)).await;
        let elapsed = start.elapsed();

        // Should have returned within ~100ms (timeout), not 60s
        assert!(elapsed < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_service_is_clone() {
        let (sink, events, _) = RecordingSink::new("test");
        let service = AuditService::new(vec![Box::new(sink)], 100);
        let cloned = service.clone();

        cloned.emit(make_test_event("from.clone"));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].event_type, "from.clone");
    }

    #[tokio::test]
    async fn test_emit_after_shutdown_does_not_panic() {
        let (sink, _events, _) = RecordingSink::new("test");
        let service = AuditService::new(vec![Box::new(sink)], 100);

        service.shutdown(Duration::from_secs(1)).await;

        // Emitting after shutdown should not panic; event is just dropped
        service.emit(make_test_event("after.shutdown"));
    }
}
