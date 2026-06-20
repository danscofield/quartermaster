// GET /billets/{name} (data-plane billet metadata)

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::cedar::{AdminAuthzRequest, CommonContext};
use crate::domain::token::Claims;
use crate::domain::DomainError;
use crate::server::AppState;

/// Response body for billet metadata.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BilletMetadataResponse {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
}

/// GET /billets/:name — retrieve billet metadata for data-plane callers.
///
/// Requires a valid Quartermaster JWT. Evaluates `readBillet` authorization
/// via the local Cedar evaluator before returning metadata.
#[utoipa::path(
    get,
    path = "/billets/{name}",
    tag = "discovery",
    params(
        ("name" = String, Path, description = "Billet name")
    ),
    responses(
        (status = 200, description = "Billet metadata", body = BilletMetadataResponse),
        (status = 401, description = "Unauthorized", body = crate::domain::ErrorBody),
        (status = 403, description = "Forbidden", body = crate::domain::ErrorBody),
        (status = 404, description = "Not found", body = crate::domain::ErrorBody),
    ),
    security(("BearerAuth" = []))
)]
pub async fn get_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // 1. Extract and verify JWT from Authorization header
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DomainError::invalid_token("missing Authorization header"))?;

    let token = extract_bearer_token(auth_header)?;

    // 2. Verify JWT signature and decode claims
    let claims = verify_quartermaster_jwt(token, &state).await?;

    // 3. Evaluate readBillet authorization via Cedar
    let authz_request = AdminAuthzRequest {
        principals: claims.billets.clone(),
        action: "readBillet".to_string(),
        resource: name.clone(),
        context: CommonContext {
            environment: String::new(),
            region: String::new(),
            request_time: chrono::Utc::now().to_rfc3339(),
            source_type: String::new(),
            source_cloud: String::new(),
            selectors: vec![],
        },
    };

    let authorized = state
        .local_authorizer
        .is_authorized_admin(authz_request, &HashMap::new())
        .await
        .map_err(|e| DomainError::service_unavailable(e.to_string()))?;

    if !authorized {
        return Err(DomainError::insufficient_scope(
            "not authorized to read this billet",
        ));
    }

    // 4. Retrieve billet metadata from DataStore
    let billet_record = state
        .data_store
        .get_billet(&name)
        .await
        .map_err(|e| DomainError::service_unavailable(e.to_string()))?
        .ok_or_else(|| DomainError::not_found(format!("billet '{}' not found", name)))?;

    Ok(Json(BilletMetadataResponse {
        name: billet_record.name,
        description: billet_record.description,
        associated_aws_roles: billet_record.associated_aws_roles,
        associated_gcp_sas: billet_record.associated_gcp_sas,
    }))
}

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(auth_header: &str) -> Result<&str, DomainError> {
    let trimmed = auth_header.trim();
    if trimmed.len() < 8 {
        return Err(DomainError::invalid_token("malformed Authorization header"));
    }
    let prefix = &trimmed[..7];
    if !prefix.eq_ignore_ascii_case("bearer ") {
        return Err(DomainError::invalid_token(
            "Authorization header must use Bearer scheme",
        ));
    }
    let token = trimmed[7..].trim();
    if token.is_empty() {
        return Err(DomainError::invalid_token("Bearer token is empty"));
    }
    Ok(token)
}

/// Verify a Quartermaster-issued JWT and return the claims.
async fn verify_quartermaster_jwt(
    token: &str,
    state: &AppState,
) -> Result<Claims, DomainError> {
    // Decode header to get kid
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| DomainError::invalid_token(format!("malformed JWT: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| DomainError::invalid_token("JWT header missing kid"))?;

    // Find key in JWKS
    let jwks = state.signing_manager.jwks();
    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| DomainError::service_unavailable("JWKS not available"))?;

    let key_entry = keys
        .iter()
        .find(|k| k["kid"].as_str() == Some(&kid))
        .ok_or_else(|| DomainError::invalid_token(format!("unknown kid: {kid}")))?;

    let x = key_entry["x"]
        .as_str()
        .ok_or_else(|| DomainError::service_unavailable("JWKS key missing x"))?;
    let y = key_entry["y"]
        .as_str()
        .ok_or_else(|| DomainError::service_unavailable("JWKS key missing y"))?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ec_components(x, y)
        .map_err(|e| DomainError::service_unavailable(format!("failed to build key: {e}")))?;

    // Validate token
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&state.issuer_url]);
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                DomainError::invalid_token("token expired")
            }
            _ => DomainError::invalid_token(format!("JWT verification failed: {e}")),
        })?;

    Ok(token_data.claims)
}
