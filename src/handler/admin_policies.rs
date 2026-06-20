// /admin/policies CRUD handlers

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::domain::admin::authenticator::AdminAuthError;
use crate::domain::admin::policies::PolicyCrudError;
use crate::domain::DomainError;
use crate::server::AppState;

/// Request body for creating a policy.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub statement: String,
    #[serde(default)]
    pub description: String,
}

/// Request body for updating a policy.
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub statement: String,
    #[serde(default)]
    pub description: String,
}

/// Response body for policy creation.
#[derive(Debug, Serialize)]
pub struct PolicyCreateResponse {
    pub policy_id: String,
    pub statement: String,
    pub description: String,
    pub created_at: String,
}

/// POST /admin/policies — create a new Cedar policy.
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "createPolicy", "policies")
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    let result = state
        .policy_crud_service
        .create(&body.statement, &body.description)
        .await
        .map_err(map_policy_error)?;

    let response = PolicyCreateResponse {
        policy_id: result.policy_id,
        statement: result.statement,
        description: result.description,
        created_at: result.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// PUT /admin/policies/:id — update an existing Cedar policy.
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "updatePolicy", &id)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    state
        .policy_crud_service
        .update(&id, &body.statement, &body.description)
        .await
        .map_err(map_policy_error)?;

    Ok(StatusCode::OK)
}

/// DELETE /admin/policies/:id — delete a Cedar policy.
pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "deletePolicy", &id)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service
    state
        .policy_crud_service
        .delete(&id)
        .await
        .map_err(map_policy_error)?;

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

/// Map PolicyCrudError to DomainError.
fn map_policy_error(err: PolicyCrudError) -> DomainError {
    match err {
        PolicyCrudError::InvalidStatement(msg) => {
            DomainError::invalid_request(format!("invalid Cedar statement: {}", msg))
        }
        PolicyCrudError::NotFound(id) => {
            DomainError::not_found(format!("policy '{}' not found", id))
        }
        PolicyCrudError::InternalError(msg) => {
            DomainError::service_unavailable(msg)
        }
    }
}
