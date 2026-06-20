# Requirements Document — Audit Logging

## Introduction

This spec enhances Quartermaster's audit logging to cover all system events (token exchange AND admin operations) and defines a pluggable sink architecture for shipping logs to durable stores. Impact analysis and policy simulation are explicitly out of scope — those are downstream consumers of the audit data, not part of the core system.

## Glossary

- **Audit_Event**: A structured record of a system action (token exchange, admin operation, policy sync, etc.)
- **Audit_Sink**: A pluggable backend that receives audit events and persists them to a durable store
- **Event_Schema**: A versioned JSON structure that downstream consumers can rely on for stable field names and types

## Requirements

### Requirement 1: Comprehensive Audit Event Types

**User Story:** As a security auditor, I want all significant system actions logged as structured audit events, so that I have a complete picture of what happened in the system.

#### Acceptance Criteria

1. THE system SHALL emit audit events for the following action categories:
   - `token.exchange.success` — successful token issuance
   - `token.exchange.failure` — failed token exchange (validation error, no billets, rate limited)
   - `admin.billet.create` — billet created
   - `admin.billet.update` — billet metadata updated
   - `admin.billet.delete` — billet deleted (cascade)
   - `admin.policy.create` — policy created
   - `admin.policy.update` — policy updated
   - `admin.policy.delete` — policy deleted
   - `admin.auth.failure` — admin authentication/authorization denied
   - `sync.policy.success` — PolicySyncService completed a successful sync
   - `sync.policy.failure` — PolicySyncService failed to sync
2. ALL audit events SHALL include: `event_type`, `timestamp`, `request_id` (unique per HTTP request), and `actor` (subject identity performing the action)
3. THE system SHALL NEVER include raw token values (JWTs, SVIDs, presigned URLs, secret values) in audit events
4. Token exchange success events SHALL include: subject, source_type, resolved billets (separated into cedar_billets and implicit_billets), audience, jti, identity_details — but NOT the access_token value
5. Admin operation events SHALL include: actor (subject from the admin JWT), action, target resource (billet name or policy id), and the result (success/failure)
6. Policy create/update events SHALL include the policy statement text (Cedar is not secret — it's config)

### Requirement 2: Pluggable Audit Sink Architecture

**User Story:** As a platform operator, I want to configure where audit logs are shipped without changing application code, so that I can route them to my organization's preferred observability/data stack.

#### Acceptance Criteria

1. THE system SHALL define an `AuditSink` trait that receives structured audit events
2. THE system SHALL support multiple sinks simultaneously (fan-out — an event goes to all configured sinks)
3. THE system SHALL support the following built-in sink implementations:
   - `stdout` — JSON lines to stdout (default)
   - `file` — JSON lines to a rotating log file
   - `kinesis_firehose` — Publish to AWS Kinesis Firehose (guaranteed delivery with ack, routes to S3/Redshift/OpenSearch)
   - `gcp_pubsub` — Publish to GCP Pub/Sub (guaranteed delivery with ack, routes to GCS/BigQuery via subscriptions)
4. Sink configuration SHALL be in the TOML config file:
   ```toml
   [[audit.sinks]]
   type = "stdout"

   [[audit.sinks]]
   type = "file"
   path = "/var/log/quartermaster/audit.jsonl"
   max_size_mb = 100
   max_files = 10

   [[audit.sinks]]
   type = "kinesis_firehose"
   stream_name = "quartermaster-audit"
   region = "us-east-1"

   [[audit.sinks]]
   type = "gcp_pubsub"
   project = "my-project"
   topic = "quartermaster-audit"
   ```
5. Sink failures SHALL NOT block the request path — audit event delivery is best-effort with a bounded in-memory buffer. If the buffer fills, oldest events are dropped and a warning is emitted
6. THE system SHALL support at least one sink configured. If no sinks are configured, default to `stdout`

### Requirement 3: Audit Event Schema

**User Story:** As a data engineer, I want audit events in a stable, well-defined schema, so that I can build queries and dashboards without brittle parsing.

#### Acceptance Criteria

1. ALL audit events SHALL conform to a versioned JSON schema with a top-level `schema_version` field (initial value: `"1.0"`)
2. THE event schema SHALL include:
   ```json
   {
     "schema_version": "1.0",
     "event_type": "token.exchange.success",
     "timestamp": "2026-06-19T22:00:00Z",
     "request_id": "uuid",
     "actor": {
       "subject": "spiffe://example.com/ns/finance/workload/payments",
       "source_type": "spire"
     },
     "details": { ... },
     "outcome": "success",
     "error": null
   }
   ```
3. THE `details` field SHALL be action-specific (different structure per `event_type`) but always present
4. Schema changes SHALL be backwards-compatible (additive only) within a major version
