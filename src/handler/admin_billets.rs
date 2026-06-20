// /admin/billets CRUD handlers

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::domain::admin::authenticator::AdminAuthError;
use crate::domain::admin::billets::BilletCrudError;
use crate::domain::admin::policies::PolicyCrudError;
use crate::domain::audit::schema::{AdminOperationDetails, AuditActor, AuditEnvelope, Outcome};
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
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Request body for updating a billet.
#[derive(Debug, Deserialize)]
pub struct UpdateBilletRequest {
    pub description: Option<String>,
    pub associated_aws_roles: Option<Vec<String>>,
    pub associated_gcp_sas: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

/// Extract the `x-request-id` header value from request headers.
fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Extract the admin subject (JWT `sub` claim) from the Authorization Bearer token.
///
/// Decodes the JWT payload (base64url) without verifying the signature,
/// since authentication has already been handled by the authenticator.
fn extract_admin_subject(auth_header: &str) -> String {
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        if let Some(payload) = token.split('.').nth(1) {
            if let Ok(decoded) =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)
            {
                if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                    if let Some(sub) = claims["sub"].as_str() {
                        return sub.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

/// Response body for a billet metadata record.
#[derive(Debug, Serialize)]
pub struct BilletMetadataResponse {
    pub name: String,
    pub description: String,
    pub associated_aws_roles: Vec<String>,
    pub associated_gcp_sas: Vec<String>,
    pub tags: Vec<String>,
    pub updated_at: String,
}

/// POST /admin/billets — create a new billet metadata record.
pub async fn create_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateBilletRequest>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "createBillet", &body.name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "createBillet".to_string(),
            target: body.name.clone(),
            policy_statement: None,
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &body.name,
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Check if billet name starts with a reserved implicit prefix
    let reserved = state.implicit_billet_mapper.reserved_prefixes();
    for prefix in reserved {
        if body.name.starts_with(&format!("{}:", prefix)) {
            return Err(DomainError::invalid_request(format!(
                "billet name '{}' uses reserved implicit prefix '{}'",
                body.name, prefix
            )));
        }
    }

    // Delegate to CRUD service
    let metadata = state
        .billet_crud_service
        .create(
            &body.name,
            &body.description,
            body.associated_aws_roles,
            body.associated_gcp_sas,
            body.tags,
        )
        .await
        .map_err(map_billet_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let details = serde_json::to_value(AdminOperationDetails {
        action: "createBillet".to_string(),
        target: metadata.name.clone(),
        policy_statement: None,
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "createBillet",
        &metadata.name,
        Outcome::Success,
        None,
        details,
    ));

    let response = BilletMetadataResponse {
        name: metadata.name,
        description: metadata.description,
        associated_aws_roles: metadata.associated_aws_roles,
        associated_gcp_sas: metadata.associated_gcp_sas,
        tags: metadata.tags,
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

/// GET /admin/billets/:name — get a single billet by name (with attached policies).
pub async fn get_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "readBillet", &name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to CRUD service — returns metadata + policies
    let billet_with_policies = state
        .billet_crud_service
        .get_with_policies(&name)
        .await
        .map_err(map_billet_error)?;

    Ok(Json(billet_with_policies))
}

/// PUT /admin/billets/:name — update a billet's metadata.
pub async fn update_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<UpdateBilletRequest>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "updateBillet", &name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "updateBillet".to_string(),
            target: name.clone(),
            policy_statement: None,
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &name,
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Delegate to CRUD service
    let metadata = state
        .billet_crud_service
        .update(
            &name,
            body.description.as_deref(),
            body.associated_aws_roles,
            body.associated_gcp_sas,
            body.tags,
        )
        .await
        .map_err(map_billet_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let details = serde_json::to_value(AdminOperationDetails {
        action: "updateBillet".to_string(),
        target: name.clone(),
        policy_statement: None,
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "updateBillet",
        &name,
        Outcome::Success,
        None,
        details,
    ));

    let response = BilletMetadataResponse {
        name: metadata.name,
        description: metadata.description,
        associated_aws_roles: metadata.associated_aws_roles,
        associated_gcp_sas: metadata.associated_gcp_sas,
        tags: metadata.tags,
        updated_at: metadata.updated_at,
    };

    Ok(Json(response))
}

/// DELETE /admin/billets/:name — delete a billet and all its attached policies (cascade).
pub async fn delete_billet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "deleteBillet", &name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "deleteBillet".to_string(),
            target: name.clone(),
            policy_statement: None,
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &name,
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Delegate to CRUD service — cascade deletes billet + all policies
    state
        .billet_crud_service
        .delete_cascade(&name)
        .await
        .map_err(map_billet_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let details = serde_json::to_value(AdminOperationDetails {
        action: "deleteBillet".to_string(),
        target: name.clone(),
        policy_statement: None,
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "deleteBillet",
        &name,
        Outcome::Success,
        None,
        details,
    ));

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

/// Request body for creating a policy under a billet.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub statement: String,
    #[serde(default)]
    pub description: String,
}

/// Request body for updating a policy under a billet.
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub statement: String,
    #[serde(default)]
    pub description: String,
}

/// Response body for a policy record.
#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub statement: String,
    pub description: String,
}

/// POST /admin/billets/{name}/policies — create a new Cedar policy under a billet.
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin with owning billet as resource
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "createPolicy", &name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "createPolicy".to_string(),
            target: name.clone(),
            policy_statement: Some(body.statement.clone()),
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &name,
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Delegate to PolicyCrudService
    let result = state
        .policy_crud_service
        .create(&name, &body.statement, &body.description)
        .await
        .map_err(map_policy_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let target = format!("{}/{}", name, result.policy_id);
    let details = serde_json::to_value(AdminOperationDetails {
        action: "createPolicy".to_string(),
        target: target.clone(),
        policy_statement: Some(body.statement.clone()),
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "createPolicy",
        &target,
        Outcome::Success,
        None,
        details,
    ));

    let response = PolicyResponse {
        id: result.policy_id,
        statement: result.statement,
        description: result.description,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /admin/billets/{name}/policies — list all policies for a billet.
pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin with owning billet as resource
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "readBillet", &name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to PolicyCrudService
    let records = state
        .policy_crud_service
        .list_for_billet(&name)
        .await
        .map_err(map_policy_error)?;

    let response: Vec<PolicyResponse> = records
        .into_iter()
        .map(|r| PolicyResponse {
            id: r.policy_id,
            statement: r.statement,
            description: r.description,
        })
        .collect();

    Ok(Json(response))
}

/// GET /admin/billets/{name}/policies/{id} — get a single policy.
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, DomainError> {
    // Authenticate admin with owning billet as resource
    let auth_header = extract_auth_header(&headers)?;
    state
        .admin_authenticator
        .authenticate(&auth_header, "readBillet", &name)
        .await
        .map_err(map_auth_error)?;

    // Delegate to PolicyCrudService
    let record = state
        .policy_crud_service
        .get(&name, &id)
        .await
        .map_err(map_policy_error)?;

    let response = PolicyResponse {
        id: record.policy_id,
        statement: record.statement,
        description: record.description,
    };

    Ok(Json(response))
}

/// PUT /admin/billets/{name}/policies/{id} — update a policy.
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, String)>,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin with owning billet as resource
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "updatePolicy", &name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "updatePolicy".to_string(),
            target: format!("{}/{}", name, id),
            policy_statement: Some(body.statement.clone()),
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &format!("{}/{}", name, id),
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Delegate to PolicyCrudService
    let record = state
        .policy_crud_service
        .update(&name, &id, &body.statement, &body.description)
        .await
        .map_err(map_policy_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let target = format!("{}/{}", name, id);
    let details = serde_json::to_value(AdminOperationDetails {
        action: "updatePolicy".to_string(),
        target: target.clone(),
        policy_statement: Some(body.statement.clone()),
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "updatePolicy",
        &target,
        Outcome::Success,
        None,
        details,
    ));

    let response = PolicyResponse {
        id: record.policy_id,
        statement: record.statement,
        description: record.description,
    };

    Ok(Json(response))
}

/// DELETE /admin/billets/{name}/policies/{id} — delete a policy.
pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, DomainError> {
    let request_id = extract_request_id(&headers);

    // Authenticate admin with owning billet as resource
    let auth_header = extract_auth_header(&headers)?;
    if let Err(ref e) = state
        .admin_authenticator
        .authenticate(&auth_header, "deletePolicy", &name)
        .await
    {
        let actor = AuditActor {
            subject: extract_admin_subject(&auth_header),
            source_type: "admin".to_string(),
        };
        let details = serde_json::to_value(AdminOperationDetails {
            action: "deletePolicy".to_string(),
            target: format!("{}/{}", name, id),
            policy_statement: None,
        })
        .unwrap_or_default();
        state.audit_service.emit(AuditEnvelope::admin_operation(
            &request_id,
            actor,
            "authFailure",
            &format!("{}/{}", name, id),
            Outcome::Failure,
            Some(&e.to_string()),
            details,
        ));
        return Err(map_auth_error(e.clone()));
    }

    // Delegate to PolicyCrudService
    state
        .policy_crud_service
        .delete(&name, &id)
        .await
        .map_err(map_policy_error)?;

    // Emit audit event on success
    let actor = AuditActor {
        subject: extract_admin_subject(&auth_header),
        source_type: "admin".to_string(),
    };
    let target = format!("{}/{}", name, id);
    let details = serde_json::to_value(AdminOperationDetails {
        action: "deletePolicy".to_string(),
        target: target.clone(),
        policy_statement: None,
    })
    .unwrap_or_default();
    state.audit_service.emit(AuditEnvelope::admin_operation(
        &request_id,
        actor,
        "deletePolicy",
        &target,
        Outcome::Success,
        None,
        details,
    ));

    Ok(StatusCode::NO_CONTENT)
}

/// Map BilletCrudError to DomainError.
fn map_billet_error(err: BilletCrudError) -> DomainError {
    match err {
        BilletCrudError::NameEmpty => {
            DomainError::invalid_request("billet name must not be empty")
        }
        BilletCrudError::InvalidTags(msg) => {
            DomainError::invalid_request(msg)
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

/// Map PolicyCrudError to DomainError.
fn map_policy_error(err: PolicyCrudError) -> DomainError {
    match err {
        PolicyCrudError::InvalidStatement(msg) => {
            DomainError::invalid_request(format!("invalid Cedar statement: {}", msg))
        }
        PolicyCrudError::InvalidResourceScope(msg) => {
            DomainError::invalid_request(format!("invalid resource scope: {}", msg))
        }
        PolicyCrudError::BilletNotFound(name) => {
            DomainError::not_found(format!("billet '{}' not found", name))
        }
        PolicyCrudError::NotFound(id) => {
            DomainError::not_found(format!("policy '{}' not found", id))
        }
        PolicyCrudError::InternalError(msg) => {
            DomainError::service_unavailable(msg)
        }
    }
}
