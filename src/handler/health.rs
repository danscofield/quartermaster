// GET /healthz

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::keymanager::KeyHealth;
use crate::server::AppState;

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthChecks {
    datastore: String,
    signing_key: String,
    policy_sync: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    status: String,
    checks: HealthChecks,
}

/// Overall health status derived from individual checks.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OverallStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// GET /healthz — health check endpoint.
///
/// Returns 200 if healthy or degraded, 503 if unhealthy.
/// Checks DataStore connectivity, KeyManager health, and PolicySync initialization.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses(
        (status = 200, description = "Service healthy or degraded", body = HealthResponse),
    )
)]
pub async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut worst_status = OverallStatus::Healthy;

    // Check DataStore health via ping()
    let datastore_check = match state.data_store.ping().await {
        Ok(()) => "healthy".to_string(),
        Err(e) => {
            worst_status = OverallStatus::Unhealthy;
            format!("unhealthy: {}", e)
        }
    };

    // Check KeyManager health
    let signing_key_check = match state.signing_key_manager.health().await {
        KeyHealth::Healthy => "healthy".to_string(),
        KeyHealth::Degraded { reason } => {
            if worst_status < OverallStatus::Degraded {
                worst_status = OverallStatus::Degraded;
            }
            format!("degraded: {}", reason)
        }
        KeyHealth::Unhealthy { reason } => {
            worst_status = OverallStatus::Unhealthy;
            format!("unhealthy: {}", reason)
        }
    };

    // Check PolicySync initialization
    let policy_sync_check = if state.policy_sync.is_initialized().await {
        "healthy".to_string()
    } else {
        if worst_status < OverallStatus::Degraded {
            worst_status = OverallStatus::Degraded;
        }
        "degraded: policy set not initialized".to_string()
    };

    let status_str = match worst_status {
        OverallStatus::Healthy => "healthy",
        OverallStatus::Degraded => "degraded",
        OverallStatus::Unhealthy => "unhealthy",
    };

    let http_status = match worst_status {
        OverallStatus::Healthy | OverallStatus::Degraded => StatusCode::OK,
        OverallStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (
        http_status,
        Json(HealthResponse {
            status: status_str.to_string(),
            checks: HealthChecks {
                datastore: datastore_check,
                signing_key: signing_key_check,
                policy_sync: policy_sync_check,
            },
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overall_status_ordering() {
        assert!(OverallStatus::Healthy < OverallStatus::Degraded);
        assert!(OverallStatus::Degraded < OverallStatus::Unhealthy);
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            checks: HealthChecks {
                datastore: "healthy".to_string(),
                signing_key: "healthy".to_string(),
                policy_sync: "healthy".to_string(),
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["checks"]["datastore"], "healthy");
        assert_eq!(json["checks"]["signing_key"], "healthy");
        assert_eq!(json["checks"]["policy_sync"], "healthy");
    }

    #[test]
    fn test_health_response_degraded_serialization() {
        let response = HealthResponse {
            status: "degraded".to_string(),
            checks: HealthChecks {
                datastore: "healthy".to_string(),
                signing_key: "degraded: key age exceeds 2x rotation_interval".to_string(),
                policy_sync: "healthy".to_string(),
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(
            json["checks"]["signing_key"],
            "degraded: key age exceeds 2x rotation_interval"
        );
    }
}
