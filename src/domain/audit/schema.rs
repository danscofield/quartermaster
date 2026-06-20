use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::IdentityAuditDetails;

/// Top-level audit event envelope conforming to schema version "1.0".
///
/// All audit events share this common structure with action-specific
/// payloads in the `details` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEnvelope {
    /// Schema version, always "1.0" for the current version.
    pub schema_version: String,
    /// Dotted action category (e.g. "token.exchange.success").
    pub event_type: String,
    /// Event creation timestamp.
    pub timestamp: DateTime<Utc>,
    /// UUID correlating all events within one HTTP request.
    pub request_id: String,
    /// Who performed the action.
    pub actor: AuditActor,
    /// Action-specific payload.
    pub details: serde_json::Value,
    /// Outcome of the action.
    pub outcome: Outcome,
    /// Error description when outcome is failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Identifies the actor who performed an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// Formatted identity (SPIFFE ID, email, ARN, etc.).
    pub subject: String,
    /// Identity source: "spire", "oidc", "aws-sts", "gcp", "system".
    pub source_type: String,
}

/// Outcome of an audited action, serialized as lowercase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
}

/// Details for token exchange audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeDetails {
    /// Billets resolved via Cedar policies.
    pub cedar_billets: Vec<String>,
    /// Billets derived from OIDC claims.
    pub implicit_billets: Vec<String>,
    /// Requested audience.
    pub audience: String,
    /// JWT ID of issued token (success only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Source-specific identity metadata.
    pub identity_details: IdentityAuditDetails,
}

/// Details for admin operation audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminOperationDetails {
    /// Admin action name (e.g. "createBillet").
    pub action: String,
    /// Target resource identifier (billet name or policy ID).
    pub target: String,
    /// Cedar statement text (for policy create/update).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_statement: Option<String>,
}

/// Details for policy sync audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDetails {
    /// Number of policies synced (success only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_count: Option<u64>,
    /// Number of billets synced (success only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billet_count: Option<u64>,
    /// Sync duration in milliseconds.
    pub duration_ms: u64,
}

impl AuditEnvelope {
    /// Construct an audit event for a successful token exchange.
    ///
    /// Sets `event_type` to `"token.exchange.success"`, `outcome` to `Success`,
    /// and serializes the provided `TokenExchangeDetails` into the `details` field.
    pub fn token_exchange_success(
        request_id: &str,
        actor: AuditActor,
        details: TokenExchangeDetails,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.success".to_string(),
            timestamp: Utc::now(),
            request_id: request_id.to_string(),
            actor,
            details: serde_json::to_value(&details)
                .expect("TokenExchangeDetails must be serializable"),
            outcome: Outcome::Success,
            error: None,
        }
    }

    /// Construct an audit event for a failed token exchange.
    ///
    /// Sets `event_type` to `"token.exchange.failure"`, `outcome` to `Failure`,
    /// and includes the error description.
    pub fn token_exchange_failure(
        request_id: &str,
        actor: AuditActor,
        error: &str,
        details: TokenExchangeDetails,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.failure".to_string(),
            timestamp: Utc::now(),
            request_id: request_id.to_string(),
            actor,
            details: serde_json::to_value(&details)
                .expect("TokenExchangeDetails must be serializable"),
            outcome: Outcome::Failure,
            error: Some(error.to_string()),
        }
    }

    /// Construct an audit event for an admin operation (billet/policy CRUD or auth failure).
    ///
    /// The `action` parameter specifies the admin action (e.g. "createBillet", "deletePolicy").
    /// The `target` parameter identifies the affected resource.
    /// The `details` field carries action-specific metadata as a pre-built JSON value.
    pub fn admin_operation(
        request_id: &str,
        actor: AuditActor,
        action: &str,
        target: &str,
        outcome: Outcome,
        error: Option<&str>,
        details: serde_json::Value,
    ) -> Self {
        let _ = target; // Used by callers for context; event_type is derived from action
        let event_type = match action {
            "createBillet" => "admin.billet.create",
            "updateBillet" => "admin.billet.update",
            "deleteBillet" => "admin.billet.delete",
            "createPolicy" => "admin.policy.create",
            "updatePolicy" => "admin.policy.update",
            "deletePolicy" => "admin.policy.delete",
            "authFailure" => "admin.auth.failure",
            other => other,
        };

        Self {
            schema_version: "1.0".to_string(),
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            request_id: request_id.to_string(),
            actor,
            details,
            outcome,
            error: error.map(|e| e.to_string()),
        }
    }

    /// Construct an audit event for a policy sync operation.
    ///
    /// Uses `"system"` as the actor source_type and generates a unique request ID
    /// since sync events are not tied to an HTTP request.
    pub fn sync_event(
        event_type: &str,
        outcome: Outcome,
        error: Option<&str>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            request_id: Uuid::new_v4().to_string(),
            actor: AuditActor {
                subject: "system".to_string(),
                source_type: "system".to_string(),
            },
            details,
            outcome,
            error: error.map(|e| e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_outcome_serializes_as_lowercase() {
        let success = serde_json::to_string(&Outcome::Success).unwrap();
        let failure = serde_json::to_string(&Outcome::Failure).unwrap();
        assert_eq!(success, "\"success\"");
        assert_eq!(failure, "\"failure\"");
    }

    #[test]
    fn test_outcome_deserializes_from_lowercase() {
        let success: Outcome = serde_json::from_str("\"success\"").unwrap();
        let failure: Outcome = serde_json::from_str("\"failure\"").unwrap();
        assert_eq!(success, Outcome::Success);
        assert_eq!(failure, Outcome::Failure);
    }

    #[test]
    fn test_audit_envelope_serialization_roundtrip() {
        let envelope = AuditEnvelope {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.success".to_string(),
            timestamp: Utc::now(),
            request_id: "test-request-id".to_string(),
            actor: AuditActor {
                subject: "spiffe://example.org/workload".to_string(),
                source_type: "spire".to_string(),
            },
            details: serde_json::json!({
                "cedar_billets": ["billing"],
                "audience": "https://api.example.com"
            }),
            outcome: Outcome::Success,
            error: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: AuditEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, "1.0");
        assert_eq!(parsed.event_type, "token.exchange.success");
        assert_eq!(parsed.request_id, "test-request-id");
        assert_eq!(parsed.actor.subject, "spiffe://example.org/workload");
        assert_eq!(parsed.actor.source_type, "spire");
        assert_eq!(parsed.outcome, Outcome::Success);
        assert!(parsed.error.is_none());
    }

    #[test]
    fn test_audit_envelope_with_error() {
        let envelope = AuditEnvelope {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.failure".to_string(),
            timestamp: Utc::now(),
            request_id: "req-456".to_string(),
            actor: AuditActor {
                subject: "human:alice@corp.example.com".to_string(),
                source_type: "oidc".to_string(),
            },
            details: serde_json::json!({}),
            outcome: Outcome::Failure,
            error: Some("token expired".to_string()),
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["outcome"], "failure");
        assert_eq!(parsed["error"], "token expired");
    }

    #[test]
    fn test_audit_envelope_error_absent_when_none() {
        let envelope = AuditEnvelope {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.success".to_string(),
            timestamp: Utc::now(),
            request_id: "req-789".to_string(),
            actor: AuditActor {
                subject: "test".to_string(),
                source_type: "spire".to_string(),
            },
            details: serde_json::json!({}),
            outcome: Outcome::Success,
            error: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn test_token_exchange_details_serialization() {
        let details = TokenExchangeDetails {
            cedar_billets: vec!["billing".to_string(), "payments".to_string()],
            implicit_billets: vec!["okta-group:ops".to_string()],
            audience: "https://api.example.com".to_string(),
            jti: Some("jti-abc-123".to_string()),
            identity_details: IdentityAuditDetails::Spire {
                spiffe_id: "spiffe://example.org/workload".to_string(),
            },
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["cedar_billets"], serde_json::json!(["billing", "payments"]));
        assert_eq!(parsed["implicit_billets"], serde_json::json!(["okta-group:ops"]));
        assert_eq!(parsed["audience"], "https://api.example.com");
        assert_eq!(parsed["jti"], "jti-abc-123");
        assert_eq!(parsed["identity_details"]["type"], "Spire");
    }

    #[test]
    fn test_token_exchange_details_jti_absent_when_none() {
        let details = TokenExchangeDetails {
            cedar_billets: vec![],
            implicit_billets: vec![],
            audience: "aud".to_string(),
            jti: None,
            identity_details: IdentityAuditDetails::Oidc {
                email: "user@example.com".to_string(),
                idp_prefix: "okta".to_string(),
                groups: vec![],
            },
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("jti").is_none());
    }

    #[test]
    fn test_admin_operation_details_serialization() {
        let details = AdminOperationDetails {
            action: "createBillet".to_string(),
            target: "billing-service".to_string(),
            policy_statement: Some("permit(principal, action, resource)".to_string()),
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["action"], "createBillet");
        assert_eq!(parsed["target"], "billing-service");
        assert_eq!(parsed["policy_statement"], "permit(principal, action, resource)");
    }

    #[test]
    fn test_admin_operation_details_policy_statement_absent_when_none() {
        let details = AdminOperationDetails {
            action: "deleteBillet".to_string(),
            target: "old-service".to_string(),
            policy_statement: None,
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("policy_statement").is_none());
    }

    #[test]
    fn test_sync_details_serialization() {
        let details = SyncDetails {
            policy_count: Some(42),
            billet_count: Some(15),
            duration_ms: 1234,
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["policy_count"], 42);
        assert_eq!(parsed["billet_count"], 15);
        assert_eq!(parsed["duration_ms"], 1234);
    }

    #[test]
    fn test_sync_details_counts_absent_on_failure() {
        let details = SyncDetails {
            policy_count: None,
            billet_count: None,
            duration_ms: 500,
        };

        let json = serde_json::to_string(&details).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("policy_count").is_none());
        assert!(parsed.get("billet_count").is_none());
        assert_eq!(parsed["duration_ms"], 500);
    }

    // --- Constructor helper tests ---

    #[test]
    fn test_token_exchange_success_constructor() {
        let actor = AuditActor {
            subject: "spiffe://example.org/workload".to_string(),
            source_type: "spire".to_string(),
        };
        let details = TokenExchangeDetails {
            cedar_billets: vec!["billing".to_string()],
            implicit_billets: vec![],
            audience: "https://api.example.com".to_string(),
            jti: Some("jti-123".to_string()),
            identity_details: IdentityAuditDetails::Spire {
                spiffe_id: "spiffe://example.org/workload".to_string(),
            },
        };

        let envelope = AuditEnvelope::token_exchange_success("req-001", actor, details);

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "token.exchange.success");
        assert_eq!(envelope.request_id, "req-001");
        assert_eq!(envelope.actor.subject, "spiffe://example.org/workload");
        assert_eq!(envelope.actor.source_type, "spire");
        assert_eq!(envelope.outcome, Outcome::Success);
        assert!(envelope.error.is_none());
        // Verify details contains expected fields
        assert_eq!(envelope.details["cedar_billets"], serde_json::json!(["billing"]));
        assert_eq!(envelope.details["audience"], "https://api.example.com");
        assert_eq!(envelope.details["jti"], "jti-123");
    }

    #[test]
    fn test_token_exchange_failure_constructor() {
        let actor = AuditActor {
            subject: "human:alice@corp.example.com".to_string(),
            source_type: "oidc".to_string(),
        };
        let details = TokenExchangeDetails {
            cedar_billets: vec![],
            implicit_billets: vec![],
            audience: "https://api.example.com".to_string(),
            jti: None,
            identity_details: IdentityAuditDetails::Oidc {
                email: "alice@corp.example.com".to_string(),
                idp_prefix: "okta".to_string(),
                groups: vec!["engineering".to_string()],
            },
        };

        let envelope = AuditEnvelope::token_exchange_failure(
            "req-002",
            actor,
            "token expired",
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "token.exchange.failure");
        assert_eq!(envelope.request_id, "req-002");
        assert_eq!(envelope.actor.subject, "human:alice@corp.example.com");
        assert_eq!(envelope.actor.source_type, "oidc");
        assert_eq!(envelope.outcome, Outcome::Failure);
        assert_eq!(envelope.error.as_deref(), Some("token expired"));
        assert_eq!(envelope.details["audience"], "https://api.example.com");
    }

    #[test]
    fn test_admin_operation_constructor_create_billet() {
        let actor = AuditActor {
            subject: "admin@corp.example.com".to_string(),
            source_type: "oidc".to_string(),
        };
        let details = serde_json::json!({
            "action": "createBillet",
            "target": "billing-service",
        });

        let envelope = AuditEnvelope::admin_operation(
            "req-003",
            actor,
            "createBillet",
            "billing-service",
            Outcome::Success,
            None,
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "admin.billet.create");
        assert_eq!(envelope.request_id, "req-003");
        assert_eq!(envelope.outcome, Outcome::Success);
        assert!(envelope.error.is_none());
        assert_eq!(envelope.details["action"], "createBillet");
        assert_eq!(envelope.details["target"], "billing-service");
    }

    #[test]
    fn test_admin_operation_constructor_delete_policy() {
        let actor = AuditActor {
            subject: "admin@corp.example.com".to_string(),
            source_type: "oidc".to_string(),
        };
        let details = serde_json::json!({
            "action": "deletePolicy",
            "target": "policy-42",
        });

        let envelope = AuditEnvelope::admin_operation(
            "req-004",
            actor,
            "deletePolicy",
            "policy-42",
            Outcome::Success,
            None,
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "admin.policy.delete");
        assert_eq!(envelope.request_id, "req-004");
        assert_eq!(envelope.outcome, Outcome::Success);
    }

    #[test]
    fn test_admin_operation_constructor_auth_failure() {
        let actor = AuditActor {
            subject: "unknown".to_string(),
            source_type: "oidc".to_string(),
        };
        let details = serde_json::json!({
            "action": "authFailure",
            "target": "",
        });

        let envelope = AuditEnvelope::admin_operation(
            "req-005",
            actor,
            "authFailure",
            "",
            Outcome::Failure,
            Some("invalid admin credentials"),
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "admin.auth.failure");
        assert_eq!(envelope.outcome, Outcome::Failure);
        assert_eq!(envelope.error.as_deref(), Some("invalid admin credentials"));
    }

    #[test]
    fn test_sync_event_constructor_success() {
        let details = serde_json::json!({
            "policy_count": 42,
            "billet_count": 15,
            "duration_ms": 1234,
        });

        let envelope = AuditEnvelope::sync_event(
            "sync.policy.success",
            Outcome::Success,
            None,
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "sync.policy.success");
        assert_eq!(envelope.actor.subject, "system");
        assert_eq!(envelope.actor.source_type, "system");
        assert_eq!(envelope.outcome, Outcome::Success);
        assert!(envelope.error.is_none());
        assert_eq!(envelope.details["policy_count"], 42);
        assert_eq!(envelope.details["billet_count"], 15);
        assert_eq!(envelope.details["duration_ms"], 1234);
        // request_id should be a valid UUID
        assert!(!envelope.request_id.is_empty());
        uuid::Uuid::parse_str(&envelope.request_id).expect("request_id should be valid UUID");
    }

    #[test]
    fn test_sync_event_constructor_failure() {
        let details = serde_json::json!({
            "duration_ms": 500,
        });

        let envelope = AuditEnvelope::sync_event(
            "sync.policy.failure",
            Outcome::Failure,
            Some("connection timeout"),
            details,
        );

        assert_eq!(envelope.schema_version, "1.0");
        assert_eq!(envelope.event_type, "sync.policy.failure");
        assert_eq!(envelope.actor.subject, "system");
        assert_eq!(envelope.actor.source_type, "system");
        assert_eq!(envelope.outcome, Outcome::Failure);
        assert_eq!(envelope.error.as_deref(), Some("connection timeout"));
    }

    #[test]
    fn test_constructors_do_not_accept_secrets() {
        // This test verifies that constructors use typed parameters
        // that don't include raw tokens, secrets, or presigned URLs.
        // The type system enforces this: TokenExchangeDetails has no field
        // for access_token, subject_token, secret, or private_key.
        let details = TokenExchangeDetails {
            cedar_billets: vec![],
            implicit_billets: vec![],
            audience: "aud".to_string(),
            jti: None,
            identity_details: IdentityAuditDetails::Spire {
                spiffe_id: "spiffe://example.org/test".to_string(),
            },
        };

        let envelope = AuditEnvelope::token_exchange_success("req-sec", AuditActor {
            subject: "test".to_string(),
            source_type: "spire".to_string(),
        }, details);

        let json = serde_json::to_string(&envelope).unwrap();
        // Verify none of the forbidden field names appear
        assert!(!json.contains("access_token"));
        assert!(!json.contains("subject_token"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("private_key"));
    }
}
