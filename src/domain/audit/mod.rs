use chrono::{DateTime, Utc};

/// Event represents a token issuance audit event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEvent {
    pub spiffe_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub billets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Logger records audit events.
pub trait AuditLogger: Send + Sync {
    /// Log records an audit event.
    fn log(&self, event: AuditEvent);
}

/// A `TracingAuditLogger` that emits audit events as structured JSON via the `tracing` crate.
///
/// On success events, it uses `tracing::info!`; on failure events, it uses `tracing::error!`.
/// All fields from the `AuditEvent` are included as structured tracing fields for proper
/// JSON log output when using `tracing-subscriber` with JSON formatting.
pub struct TracingAuditLogger;

impl TracingAuditLogger {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TracingAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for TracingAuditLogger {
    fn log(&self, event: AuditEvent) {
        let billets = serde_json::to_string(&event.billets).unwrap_or_default();
        let audience = event.audience.as_deref().unwrap_or("");
        let jti = event.jti.as_deref().unwrap_or("");
        let timestamp = event.timestamp.to_rfc3339();
        let error_msg = event.error.as_deref().unwrap_or("");

        if event.success {
            tracing::info!(
                target: "audit",
                spiffe_id = %event.spiffe_id,
                billets = %billets,
                audience = %audience,
                jti = %jti,
                timestamp = %timestamp,
                success = event.success,
                error = %error_msg,
                "audit_event"
            );
        } else {
            tracing::error!(
                target: "audit",
                spiffe_id = %event.spiffe_id,
                billets = %billets,
                audience = %audience,
                jti = %jti,
                timestamp = %timestamp,
                success = event.success,
                error = %error_msg,
                "audit_event"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_audit_event_serializes_to_valid_json() {
        let event = AuditEvent {
            spiffe_id: "spiffe://example.org/workload".to_string(),
            billets: vec!["billing".to_string(), "payments".to_string()],
            audience: Some("https://api.example.com".to_string()),
            jti: Some("abc-123-def".to_string()),
            timestamp: Utc::now(),
            success: true,
            error: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["spiffe_id"], "spiffe://example.org/workload");
        assert_eq!(parsed["billets"], serde_json::json!(["billing", "payments"]));
        assert_eq!(parsed["audience"], "https://api.example.com");
        assert_eq!(parsed["jti"], "abc-123-def");
        assert_eq!(parsed["success"], true);
        // error field should be absent due to skip_serializing_if
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn test_audit_event_skips_empty_billets() {
        let event = AuditEvent {
            spiffe_id: "spiffe://example.org/workload".to_string(),
            billets: vec![],
            audience: None,
            jti: None,
            timestamp: Utc::now(),
            success: false,
            error: Some("token expired".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // billets field should be absent due to skip_serializing_if
        assert!(parsed.get("billets").is_none());
        // audience and jti should be absent
        assert!(parsed.get("audience").is_none());
        assert!(parsed.get("jti").is_none());
        // error should be present
        assert_eq!(parsed["error"], "token expired");
        assert_eq!(parsed["success"], false);
    }

    #[test]
    fn test_audit_event_includes_timestamp() {
        let now = Utc::now();
        let event = AuditEvent {
            spiffe_id: "spiffe://trust.domain/svc".to_string(),
            billets: vec!["admin".to_string()],
            audience: Some("aud".to_string()),
            jti: Some("jti-1".to_string()),
            timestamp: now,
            success: true,
            error: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Timestamp should be present and non-empty
        let ts = parsed["timestamp"].as_str().unwrap();
        assert!(!ts.is_empty());
    }

    #[test]
    fn test_tracing_audit_logger_does_not_panic_on_success() {
        let logger = TracingAuditLogger::new();
        let event = AuditEvent {
            spiffe_id: "spiffe://example.org/workload".to_string(),
            billets: vec!["billing".to_string()],
            audience: Some("https://api.example.com".to_string()),
            jti: Some("abc-123".to_string()),
            timestamp: Utc::now(),
            success: true,
            error: None,
        };
        // Should not panic
        logger.log(event);
    }

    #[test]
    fn test_tracing_audit_logger_does_not_panic_on_failure() {
        let logger = TracingAuditLogger::new();
        let event = AuditEvent {
            spiffe_id: "spiffe://example.org/workload".to_string(),
            billets: vec![],
            audience: None,
            jti: None,
            timestamp: Utc::now(),
            success: false,
            error: Some("invalid SVID".to_string()),
        };
        // Should not panic
        logger.log(event);
    }

    #[test]
    fn test_tracing_audit_logger_default() {
        let _logger = TracingAuditLogger::default();
    }
}
