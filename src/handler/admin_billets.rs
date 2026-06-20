// /admin/billets CRUD handlers

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::domain::admin::authenticator::AdminAuthError;
use crate::domain::admin::billets::BilletCrudError;
use crate::domain::DomainError;
use crate::server::AppState;

/// Request body for creating a billet.
#[derive(Debug, Deserialize)]
pub struct CreateBilletRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub associated_aws_roles: Vec<String>,
    #[serde(default)]
    pub associated_gcp_sas: Vec<String>,
}

/// Response body for a billet metadata record.
#[derive(Debug, Serialize)]
pub struct BilletMetadataResponse {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub updated_at: String,
}

/// POST /admin/billets — create a new billet metadata record.
pub async fn create_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateBilletRequest>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "createBillet", &body.name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    let metadata = state
        .billet_crud_service
        .create(
            &body.name,
            &body.description,
            body.associated_aws_roles,
            body.associated_gcp_sas,
        )
        .await
        .map_err(map_billet_error)?;

    let response = BilletMetadataResponse {
        name: metadata.name,
        description: metadata.description,
        associated_aws_roles: metadata.associated_aws_roles,
        associated_gcp_sas: metadata.associated_gcp_sas,
        updated_at: metadata.updated_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /admin/billets — list all billets.
pub async fn list_billets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "listBillets", "billets")
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    let items = state
        .billet_crud_service
        .list()
        .await
        .map_err(map_billet_error)?;

    Ok(Json(items))
}

/// GET /admin/billets/:name — get a single billet by name.
pub async fn get_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "getBillet", &name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    let metadata = state
        .billet_crud_service
        .get(&name)
        .await
        .map_err(map_billet_error)?;

    let response = BilletMetadataResponse {
        name: metadata.name,
        description: metadata.description,
        associated_aws_roles: metadata.associated_aws_roles,
        associated_gcp_sas: metadata.associated_gcp_sas,
        updated_at: metadata.updated_at,
    };

    Ok(Json(response))
}

/// DELETE /admin/billets/:name — delete a billet by name.
pub async fn delete_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "deleteBillet", &name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    state
        .billet_crud_service
        .delete(&name)
        .await
        .map_err(map_billet_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Extract the Authorization header value from request headers.
fn extract_auth_header(headers: &HeaderMap) -> Result<String, DomainError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| DomainError::invalid_token("missing Authorization header"))
}

/// Map AdminAuthError to DomainError.
fn map_auth_error(err: AdminAuthError) -> DomainError {
    match err {
        AdminAuthError::MissingCredentials => {
            DomainError::invalid_token("missing or malformed credentials")
        }
        AdminAuthError::InvalidToken(msg) => DomainError::invalid_token(msg),
        AdminAuthError::TokenExpired => DomainError::invalid_token("token expired"),
        AdminAuthError::InsufficientPrivileges => {
            DomainError::insufficient_scope("insufficient privileges")
        }
    }
}

/// Map BilletCrudError to DomainError.
fn map_billet_error(err: BilletCrudError) -> DomainError {
    match err {
        BilletCrudError::NameEmpty => {
            DomainError::invalid_request("billet name must not be empty")
        }
        BilletCrudError::AlreadyExists(name) => {
            DomainError::conflict(format!("billet '{}' already exists", name))
        }
        BilletCrudError::NotFound(name) => {
            DomainError::not_found(format!("billet '{}' not found", name))
        }
        BilletCrudError::ProtectedBillet(name) => {
            DomainError::insufficient_scope(format!(
                "billet '{}' is protected and cannot be deleted",
                name
            ))
        }
        BilletCrudError::InternalError(msg) => {
            DomainError::service_unavailable(msg)
        }
    }
}
