// GET /.well-known/openid-configuration

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::oidc::DiscoveryDocument;
use crate::server::AppState;

/// GET /.well-known/openid-configuration — returns the OIDC discovery document.
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "discovery",
    responses(
        (status = 200, description = "OIDC discovery document", body = crate::oidc::DiscoveryDocument),
    )
)]
pub async fn openid_configuration(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let doc = DiscoveryDocument::new(&state.issuer_url, &state.algorithm);
    Json(doc)
}
