# Implementation Plan: Audit Logging

## Overview

This plan incrementally implements the new audit logging system for Quartermaster, replacing the existing `AuditLogger` trait with a comprehensive `AuditService` that supports a versioned event schema, pluggable sink architecture, async bounded-channel event bus, and fan-out to multiple backends. Each task builds on the previous, culminating in full integration across token handlers, admin handlers, and PolicySyncService.

## Tasks

- [x] 1. Define core audit data models and event schema
  - [x] 1.1 Create `AuditEnvelope`, `AuditActor`, `Outcome`, and detail structs
    - Create file `src/domain/audit/schema.rs`
    - Define `AuditEnvelope` with fields: `schema_version`, `event_type`, `timestamp`, `request_id`, `actor`, `details`, `outcome`, `error`
    - Define `AuditActor` with `subject` and `source_type` fields
    - Define `Outcome` enum with `Success` and `Failure` variants, serialized as lowercase
    - Define `TokenExchangeDetails`, `AdminOperationDetails`, `SyncDetails` structs
    - Derive `Serialize`, `Deserialize`, `Debug`, `Clone` on all types
    - _Requirements: 1.2, 3.1, 3.2, 3.3_

  - [x] 1.2 Implement `AuditEnvelope` constructor helpers
    - Add `token_exchange_success()`, `token_exchange_failure()` constructors
    - Add `admin_operation()` constructor for all admin CRUD event types
    - Add `sync_event()` constructor for policy sync events
    - Constructors must set `schema_version` to `"1.0"` and populate all required fields
    - Constructors must NOT accept raw tokens, secrets, or presigned URLs as parameters
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6, 3.1_

  - [ ]* 1.3 Write property test: Schema Structure Invariant (Property 1)
    - **Property 1: Schema Structure Invariant**
    - Generate arbitrary `AuditEnvelope` instances using proptest strategies for each event type
    - Serialize to JSON and assert: `schema_version` == `"1.0"`, `actor` has `subject` + `source_type`, `details` is non-null, all required top-level fields present
    - **Validates: Requirements 1.2, 3.1, 3.2, 3.3**

  - [ ]* 1.4 Write property test: No Secrets in Serialized Events (Property 2)
    - **Property 2: No Secrets in Serialized Events**
    - Generate events with random identity details, serialize to JSON
    - Regex-scan for JWT patterns (base64url dot-separated triple), forbidden field names (`access_token`, `subject_token`, `secret`, `private_key`), and presigned URL query parameters
    - **Validates: Requirements 1.3**

  - [ ]* 1.5 Write property test: Event-Type-Specific Details Completeness (Property 3)
    - **Property 3: Event-Type-Specific Details Completeness**
    - Generate events per type, deserialize the `details` field
    - Verify: token exchange events contain `cedar_billets`, `implicit_billets`, `audience`, `identity_details`; admin events contain `action` and `target`; policy mutation admin events additionally contain `policy_statement`
    - **Validates: Requirements 1.4, 1.5, 1.6**

- [x] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Implement the `AuditSink` trait and `StdoutSink`
  - [x] 3.1 Define the `AuditSink` trait
    - Create file `src/domain/audit/sink.rs`
    - Define `#[async_trait] pub trait AuditSink: Send + Sync` with `send_batch()`, `flush()`, and `name()` methods
    - Define `SinkError` type for sink failures
    - _Requirements: 2.1_

  - [x] 3.2 Implement `StdoutSink`
    - Create file `src/domain/audit/stdout_sink.rs`
    - Implement `AuditSink` for `StdoutSink`: serialize each event to JSON and write as a line to `tokio::io::stdout()`
    - `send_batch` iterates events and writes each immediately
    - `flush` is a no-op (stdout is unbuffered)
    - _Requirements: 2.3_

  - [ ]* 3.3 Write unit tests for `StdoutSink`
    - Verify `StdoutSink` produces valid JSON lines
    - Verify `name()` returns `"stdout"`
    - _Requirements: 2.3_

- [x] 4. Implement `AuditService` with bounded channel and fan-out dispatcher
  - [x] 4.1 Create `AuditService` struct with bounded mpsc channel
    - Create file `src/domain/audit/service.rs`
    - Implement `AuditService::new(sinks, buffer_capacity)` that creates a bounded `tokio::sync::mpsc` channel and spawns the background fan-out task
    - Implement `emit(&self, event: AuditEnvelope)` using `try_send`; on `TrySendError::Full`, increment `overflow_dropped` counter and log warning
    - Make `AuditService` `Clone` (wraps `Arc<AuditServiceInner>`)
    - _Requirements: 2.5_

  - [x] 4.2 Implement background fan-out dispatcher task
    - In the spawned task, loop on `receiver.recv()` and for each event, call `send_batch(&[event])` on all configured sinks sequentially
    - If a sink returns an error, log a warning with the sink name and error, continue to next sink
    - On channel close (all senders dropped), drain remaining events, call `flush()` on all sinks, then exit
    - _Requirements: 2.2_

  - [x] 4.3 Implement `shutdown()` method with timeout
    - Send shutdown signal via `tokio::sync::watch` channel
    - Background task drains remaining events from mpsc channel, calls `flush()` on all sinks
    - `shutdown()` awaits task completion with a configurable timeout (default 5s)
    - After timeout, remaining events are dropped
    - _Requirements: 2.5_

  - [ ]* 4.4 Write property test: Fan-Out Delivery to All Sinks (Property 4)
    - **Property 4: Fan-Out Delivery to All Sinks**
    - Create N mock sinks (in-memory `Vec<AuditEnvelope>`)
    - Emit random events through AuditService, call shutdown to flush
    - Verify all N sinks received exactly one copy of each event
    - **Validates: Requirements 2.2**

  - [ ]* 4.5 Write property test: Non-Blocking Emit with Bounded Buffer Overflow (Property 6)
    - **Property 6: Non-Blocking Emit with Bounded Buffer Overflow**
    - Create AuditService with capacity=1 and a slow/blocking mock sink
    - Emit N events rapidly; verify `emit()` returns immediately (never blocks)
    - Verify drop counter equals N minus the number of events successfully received
    - **Validates: Requirements 2.5**

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement `FileSink` with rotation
  - [x] 6.1 Implement `FileSink` struct
    - Create file `src/domain/audit/file_sink.rs`
    - Implement line-buffered writes of JSON-serialized events to a file
    - Implement log rotation: rotate when file exceeds `max_size_mb`, keep at most `max_files` rotated files
    - `flush()` forces write of any buffered content
    - _Requirements: 2.3_

  - [ ]* 6.2 Write unit tests for `FileSink`
    - Test rotation triggers at boundary
    - Test old files are cleaned up when `max_files` exceeded
    - Test `flush()` writes pending buffer
    - _Requirements: 2.3_

- [x] 7. Implement `KinesisFirehoseSink`
  - [x] 7.1 Implement `KinesisFirehoseSink` struct
    - Create file `src/domain/audit/kinesis_sink.rs`
    - Buffer events internally; flush when count reaches 500 or 1-second interval elapses
    - Use `aws-sdk-firehose` `PutRecordBatch` API (up to 500 records per call)
    - `flush()` sends any buffered records immediately
    - _Requirements: 2.3_

  - [ ]* 7.2 Write unit tests for `KinesisFirehoseSink`
    - Test batching logic: batch flushes at 500 records
    - Test `flush()` sends partial batch
    - Use mock Firehose client
    - _Requirements: 2.3_

- [x] 8. Implement `GcpPubSubSink`
  - [x] 8.1 Implement `GcpPubSubSink` struct
    - Create file `src/domain/audit/pubsub_sink.rs`
    - Buffer events internally; flush when count reaches 1000 or 1-second interval elapses
    - Use batch publish API for GCP Pub/Sub
    - `flush()` sends any buffered messages immediately
    - _Requirements: 2.3_

  - [ ]* 8.2 Write unit tests for `GcpPubSubSink`
    - Test batching logic: batch flushes at 1000 messages
    - Test `flush()` sends partial batch
    - Use mock Pub/Sub client
    - _Requirements: 2.3_

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement TOML configuration parsing for audit sinks
  - [x] 10.1 Define `AuditConfig` and `SinkConfig` structs
    - Add `AuditConfig` struct with `buffer_capacity` (default 10_000) and `sinks: Vec<SinkConfig>`
    - Define `SinkConfig` enum with variants: `Stdout`, `File { path, max_size_mb, max_files }`, `KinesisFirehose { stream_name, region }`, `GcpPubSub { project, topic }`
    - Use `#[serde(tag = "type")]` for TOML deserialization
    - Add `audit: Option<AuditConfig>` to the main `Config` struct
    - Implement default: if no sinks configured, default to `[SinkConfig::Stdout]`
    - _Requirements: 2.4, 2.6_

  - [x] 10.2 Implement sink factory function
    - Create `build_sinks(config: &AuditConfig) -> Vec<Box<dyn AuditSink>>` that instantiates concrete sinks from `SinkConfig` variants
    - _Requirements: 2.4_

  - [ ]* 10.3 Write property test: Sink Configuration Round-Trip (Property 5)
    - **Property 5: Sink Configuration Round-Trip**
    - Generate random valid `AuditConfig` with non-empty sink lists using proptest
    - Serialize to TOML, parse back, assert equivalence (same sink types, same parameters)
    - **Validates: Requirements 2.4**

  - [ ]* 10.4 Write unit tests for config defaults
    - Test that missing `[audit]` section yields default `AuditConfig` with stdout sink
    - Test that empty `[[audit.sinks]]` list defaults to stdout
    - _Requirements: 2.6_

- [x] 11. Integrate `AuditService` into `AppState` and startup
  - [x] 11.1 Replace `audit_logger` with `audit_service` in `AppState`
    - In `src/server/mod.rs`: replace `audit_logger: Arc<dyn AuditLogger>` with `audit_service: AuditService`
    - Update `AppState` struct definition and all references
    - _Requirements: 2.1_

  - [x] 11.2 Wire `AuditService` construction in `main.rs`
    - Parse `AuditConfig` from the TOML config
    - Call `build_sinks()` to create sink instances
    - Construct `AuditService::new(sinks, config.audit.buffer_capacity)`
    - Replace the `TracingAuditLogger` initialization with `AuditService`
    - Add `audit_service.shutdown()` call during graceful shutdown
    - _Requirements: 2.1, 2.4_

- [x] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Integrate audit events into token exchange handler
  - [x] 13.1 Extract request ID from request extensions
    - In `src/handler/token.rs`, extract `x-request-id` from the request headers/extensions
    - Pass `request_id` to all `AuditEnvelope` constructors
    - _Requirements: 1.2_

  - [x] 13.2 Replace `audit_logger.log()` calls with `audit_service.emit()`
    - Replace the validation failure audit log with `AuditEnvelope::token_exchange_failure()`
    - Replace the rate-limit failure audit log with `AuditEnvelope::token_exchange_failure()`
    - Replace the billet resolution failure audit log with `AuditEnvelope::token_exchange_failure()`
    - Replace the success audit log with `AuditEnvelope::token_exchange_success()`
    - Ensure `event_type` is set correctly: `token.exchange.success` or `token.exchange.failure`
    - _Requirements: 1.1, 1.4_

  - [ ]* 13.3 Write integration test for token exchange audit events
    - Use a test sink (in-memory) to capture emitted events
    - POST `/token` with valid credentials, verify `token.exchange.success` event emitted with correct structure
    - POST `/token` with invalid token, verify `token.exchange.failure` event emitted
    - _Requirements: 1.1, 1.4_

- [x] 14. Integrate audit events into admin handlers
  - [x] 14.1 Add audit event emission to billet CRUD handlers
    - In `src/handler/admin_billets.rs`, emit `admin.billet.create`, `admin.billet.update`, `admin.billet.delete` events on success
    - Emit `admin.auth.failure` when admin authentication fails
    - Extract request ID from headers for each event
    - Include `action`, `target`, and `outcome` in event details
    - _Requirements: 1.1, 1.5_

  - [x] 14.2 Add audit event emission to policy CRUD handlers
    - Emit `admin.policy.create`, `admin.policy.update`, `admin.policy.delete` events on success
    - Include `policy_statement` text in create/update events
    - Emit `admin.auth.failure` when admin authentication fails for policy operations
    - _Requirements: 1.1, 1.5, 1.6_

  - [ ]* 14.3 Write integration tests for admin audit events
    - Verify each admin CRUD operation emits the correct event type
    - Verify `admin.auth.failure` is emitted on failed auth
    - Verify policy statement is included in policy create/update events
    - Verify no sensitive headers are leaked in events
    - _Requirements: 1.1, 1.5, 1.6_

- [x] 15. Integrate audit events into PolicySyncService
  - [x] 15.1 Add `AuditService` to `PolicySyncService`
    - Pass `AuditService` into `PolicySyncService::new()`
    - After each `sync_once()` call, emit `sync.policy.success` or `sync.policy.failure`
    - Include `policy_count`, `billet_count`, and `duration_ms` in sync event details
    - Use `"system"` as the actor source_type for sync events
    - _Requirements: 1.1_

  - [ ]* 15.2 Write unit test for sync audit events
    - Use mock sinks to verify sync events are emitted with correct structure
    - Verify success event includes counts, failure event includes error message
    - _Requirements: 1.1_

- [ ] 16. Ensure request ID is accessible to all audit emit sites
  - [x] 16.1 Propagate request ID via request extension
    - In `src/server/middleware.rs`, ensure the generated `x-request-id` is inserted into request extensions (not just headers) so handlers can extract it via `Extension<RequestId>`
    - Create a `RequestId` newtype wrapper for type safety
    - Update token and admin handlers to extract `RequestId` from extensions
    - _Requirements: 1.2_

  - [ ]* 16.2 Write unit test for request ID propagation
    - Verify every audit event within a single request shares the same `request_id`
    - _Requirements: 1.2_

- [x] 17. Remove old `AuditLogger` trait and `TracingAuditLogger`
  - [x] 17.1 Remove deprecated audit types
    - Remove `AuditLogger` trait definition from `src/domain/audit/mod.rs`
    - Remove `TracingAuditLogger` struct and its `impl`
    - Remove old `AuditEvent` struct (replaced by `AuditEnvelope`)
    - Update `src/domain/audit/mod.rs` to re-export new types: `AuditService`, `AuditEnvelope`, `AuditSink`, etc.
    - Remove `AuditLogger` import from `src/lib.rs` and any other modules
    - _Requirements: 2.1_

  - [ ]* 17.2 Verify no compilation errors after removal
    - Run `cargo build` to confirm clean compilation
    - Run `cargo test` to confirm all tests pass
    - _Requirements: 2.1_

- [x] 18. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (6 properties total)
- The existing `AuditLogger` trait is removed only after all new integrations are wired, minimizing breakage
- `aws-sdk-firehose` and a GCP Pub/Sub crate will need to be added to `Cargo.toml` dependencies when implementing tasks 7 and 8
