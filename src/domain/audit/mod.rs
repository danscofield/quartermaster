pub mod config;
pub mod file_sink;
pub mod kinesis_sink;
pub mod pubsub_sink;
pub mod schema;
pub mod service;
pub mod sink;
pub mod stdout_sink;

// Re-export the new public API
pub use schema::{AuditEnvelope, AuditActor, Outcome, TokenExchangeDetails, AdminOperationDetails, SyncDetails};
pub use service::AuditService;
pub use sink::{AuditSink, SinkError};

/// Source-specific identity details for audit logging.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum IdentityAuditDetails {
    Spire { spiffe_id: String },
    Oidc { email: String, idp_prefix: String, groups: Vec<String> },
    AwsSts { account_id: String, role_arn: String },
    Gcp { project_id: String, service_account_email: String },
}
