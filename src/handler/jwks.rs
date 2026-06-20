// GET /jwks.json

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::server::AppState;

/// GET /jwks.json — returns the JSON Web Key Set for token verification.
pub async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.signing_manager.jwks().clone())
}
