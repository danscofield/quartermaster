// GET /healthz

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// GET /healthz — health check endpoint.
///
/// Returns 200 if healthy (PolicySet loaded), 503 if service is degraded.
/// Does NOT check DynamoDB reachability on every request (sync loop handles that).
pub async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check: PolicySet has been loaded at least once (first DynamoDB sync succeeded)
    let policy_initialized = state.policy_sync.is_initialized().await;

    if policy_initialized {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "healthy",
                reason: None,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "degraded",
                reason: Some("policy set not initialized".to_string()),
            }),
        )
    }
}
