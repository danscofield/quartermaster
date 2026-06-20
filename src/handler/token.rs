// POST /token handler

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Form;
use serde::{Deserialize, Serialize};

use crate::domain::audit::AuditEvent;
use crate::domain::billet::{BilletError, ResolverInput};
use crate::domain::cert::CertIssueRequest;
use crate::domain::token::IssueRequest;
use crate::domain::{DomainError, ErrorCode};
use crate::server::AppState;

/// Form body for the token exchange request (application/x-www-form-urlencoded).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeForm {
    pub grant_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub audience: Option<String>,
    pub csr: Option<String>,
}

/// JSON response for a successful token exchange.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<String>,
}

/// POST /token — RFC 8693 token exchange endpoint.
///
/// Orchestrates: rate limit → validate SVID → resolve billets → issue JWT
/// → (optional) issue cert → audit log → return response.
pub async fn token_exchange(
    State(state): State<Arc<AppState>>,
    Form(form): Form<TokenExchangeForm>,
) -> Result<impl IntoResponse, DomainError> {
    // 1. Validate required parameters
    let grant_type = form.grant_type.unwrap_or_default();
    if grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
        return Err(DomainError::invalid_request(
            "grant_type must be urn:ietf:params:oauth:grant-type:token-exchange",
        ));
    }

    let subject_token = form.subject_token.ok_or_else(|| {
        DomainError::invalid_request("subject_token is required")
    })?;

    let subject_token_type = form.subject_token_type.unwrap_or_default();
    if subject_token_type != "urn:ietf:params:oauth:token-type:jwt" {
        return Err(DomainError::invalid_request(
            "subject_token_type must be urn:ietf:params:oauth:token-type:jwt",
        ));
    }

    let audience = form.audience.ok_or_else(|| {
        DomainError::invalid_request("audience is required")
    })?;

    // 2. Validate SVID (get spiffe_id for rate limiting)
    let claims = state.validator.validate(&subject_token).await.map_err(|e| {
        // Log failed attempt
        state.audit_logger.log(AuditEvent {
            spiffe_id: String::new(),
            billets: vec![],
            audience: Some(audience.clone()),
            jti: None,
            timestamp: chrono::Utc::now(),
            success: false,
            error: Some(e.to_string()),
        });
        match e {
            crate::domain::svid::SvidError::Expired
            | crate::domain::svid::SvidError::SignatureInvalid(_)
            | crate::domain::svid::SvidError::MalformedToken(_) => {
                DomainError::invalid_token(e.to_string())
            }
            crate::domain::svid::SvidError::UnknownTrustDomain(_) => {
                DomainError::invalid_token(e.to_string())
            }
            crate::domain::svid::SvidError::InvalidAudience => {
                DomainError::invalid_token(e.to_string())
            }
        }
    })?;

    let spiffe_id = claims.spiffe_id.clone();

    // 3. Rate limit check
    let allowed = state.rate_limiter.allow(&spiffe_id).await.map_err(|e| {
        DomainError::new(ErrorCode::ServiceUnavailable, e.to_string())
    })?;

    if !allowed {
        state.audit_logger.log(AuditEvent {
            spiffe_id: spiffe_id.clone(),
            billets: vec![],
            audience: Some(audience.clone()),
            jti: None,
            timestamp: chrono::Utc::now(),
            success: false,
            error: Some("rate limit exceeded".to_string()),
        });
        return Err(DomainError::rate_limited("rate limit exceeded"));
    }

    // 4. Resolve billets
    let resolver_input = ResolverInput {
        spiffe_id: spiffe_id.clone(),
        trust_domain: claims.trust_domain.clone(),
        environment: claims.environment.clone(),
        region: claims.region.clone(),
        audience: audience.clone(),
        request_time: chrono::Utc::now(),
        source_cloud: String::new(),
        selectors: vec![],
    };

    let resolution = state.resolver.resolve(resolver_input).await.map_err(|e| {
        state.audit_logger.log(AuditEvent {
            spiffe_id: spiffe_id.clone(),
            billets: vec![],
            audience: Some(audience.clone()),
            jti: None,
            timestamp: chrono::Utc::now(),
            success: false,
            error: Some(e.to_string()),
        });
        match e {
            BilletError::NoBilletsResolved => {
                DomainError::insufficient_scope("workload holds no billets")
            }
            BilletError::PolicySetNotInitialized => {
                DomainError::service_unavailable("policy set not initialized")
            }
            BilletError::InternalError(msg) => {
                DomainError::service_unavailable(msg)
            }
        }
    })?;

    // 5. Issue JWT
    let issue_req = IssueRequest {
        spiffe_id: spiffe_id.clone(),
        audience: audience.clone(),
        billets: resolution.billets.clone(),
    };

    let issue_resp = state.issuer.issue(issue_req).await.map_err(|e| {
        DomainError::service_unavailable(e.to_string())
    })?;

    // 6. (Optional) Issue certificate if CSR provided
    let certificate_chain = if let Some(csr_b64) = form.csr {
        let csr_der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &csr_b64,
        )
        .map_err(|e| DomainError::invalid_request(format!("invalid CSR base64: {e}")))?;

        let cert_req = CertIssueRequest {
            csr_der,
            spiffe_id: spiffe_id.clone(),
            billets: resolution.billets.clone(),
        };

        let cert_resp = state.authority.issue(cert_req).await.map_err(|e| {
            DomainError::invalid_request(e.to_string())
        })?;

        Some(String::from_utf8_lossy(&cert_resp.chain_pem).to_string())
    } else {
        None
    };

    // 7. Audit log success
    state.audit_logger.log(AuditEvent {
        spiffe_id: spiffe_id.clone(),
        billets: resolution.billets.clone(),
        audience: Some(audience.clone()),
        jti: Some(issue_resp.jti.clone()),
        timestamp: chrono::Utc::now(),
        success: true,
        error: None,
    });

    // 8. Build response
    let response = TokenExchangeResponse {
        access_token: issue_resp.access_token,
        issued_token_type: issue_resp.issued_token_type,
        token_type: issue_resp.token_type,
        expires_in: issue_resp.expires_in,
        certificate_chain,
    };

    Ok(axum::Json(response))
}
