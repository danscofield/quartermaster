// GET /ca/chain.pem

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::server::AppState;

/// GET /ca/chain.pem — returns the CA certificate chain in PEM format.
pub async fn ca_chain(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pem = state.authority.chain_pem();
    (
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        pem.to_vec(),
    )
}
