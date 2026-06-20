// POST /token handler

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Form;
use serde::{Deserialize, Serialize};

use crate::domain::audit::IdentityAuditDetails;
use crate::domain::audit::schema::{AuditActor, AuditEnvelope, TokenExchangeDetails};
use crate::domain::billet::{BilletError, ResolverInput};
use crate::domain::cert::CertIssueRequest;
use crate::domain::identity::claims::build_identity_claim;
use crate::domain::identity::entity::source_type_for_identity;
use crate::domain::identity::implicit::assemble_token_billets;
use crate::domain::identity::subject::format_subject;
use crate::domain::identity::{AuthenticatedIdentity, IdentityError};
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
/// Orchestrates: validate identity → rate limit → resolve billets → implicit mapping
/// → token assembly → issue JWT → (optional) issue cert → audit log → return response.
pub async fn token_exchange(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<TokenExchangeForm>,
) -> Result<impl IntoResponse, DomainError> {
    // Extract request ID from middleware-generated header
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
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

    let subject_token_type = form.subject_token_type.ok_or_else(|| {
        DomainError::invalid_request("subject_token_type is required")
    })?;

    let audience = form.audience.ok_or_else(|| {
        DomainError::invalid_request("audience is required")
    })?;

    // 2. Dispatch to IdentityDispatcher to validate the subject token
    let identity = state
        .identity_dispatcher
        .validate(&subject_token, &subject_token_type)
        .await
        .map_err(|e| {
            // Log failed validation attempt
            let actor = AuditActor {
                subject: String::new(),
                source_type: source_type_from_token_type(&subject_token_type),
            };
            let details = TokenExchangeDetails {
                cedar_billets: vec![],
                implicit_billets: vec![],
                audience: audience.clone(),
                jti: None,
                identity_details: IdentityAuditDetails::Spire {
                    spiffe_id: String::new(),
                },
            };
            state.audit_service.emit(
                AuditEnvelope::token_exchange_failure(&request_id, actor, &e.to_string(), details)
            );
            identity_error_to_domain_error(e)
        })?;

    // 3. Format subject and determine source type
    let subject = format_subject(&identity);
    let source_type = source_type_for_identity(&identity).to_string();

    // 4. Rate limit check (keyed by formatted subject)
    let allowed = state.rate_limiter.allow(&subject).await.map_err(|e| {
        DomainError::new(ErrorCode::ServiceUnavailable, e.to_string())
    })?;

    if !allowed {
        let actor = AuditActor {
            subject: subject.clone(),
            source_type: source_type.clone(),
        };
        let details = TokenExchangeDetails {
            cedar_billets: vec![],
            implicit_billets: vec![],
            audience: audience.clone(),
            jti: None,
            identity_details: build_identity_audit_details(&identity),
        };
        state.audit_service.emit(
            AuditEnvelope::token_exchange_failure(&request_id, actor, "rate limit exceeded", details)
        );
        return Err(DomainError::rate_limited("rate limit exceeded"));
    }

    // 5. Resolve billets via Cedar evaluation
    //    For SPIRE: use the spiffe_id directly (backward compat).
    //    For other sources: use the formatted subject as the resolver key.
    let resolver_input = build_resolver_input(&identity, &subject, &audience);

    let resolution = state.resolver.resolve(resolver_input).await.map_err(|e| {
        let actor = AuditActor {
            subject: subject.clone(),
            source_type: source_type.clone(),
        };
        let details = TokenExchangeDetails {
            cedar_billets: vec![],
            implicit_billets: vec![],
            audience: audience.clone(),
            jti: None,
            identity_details: build_identity_audit_details(&identity),
        };
        state.audit_service.emit(
            AuditEnvelope::token_exchange_failure(&request_id, actor, &e.to_string(), details)
        );
        match e {
            BilletError::NoBilletsResolved => {
                DomainError::insufficient_scope("identity holds no billets")
            }
            BilletError::PolicySetNotInitialized => {
                DomainError::service_unavailable("policy set not initialized")
            }
            BilletError::InternalError(msg) => {
                DomainError::service_unavailable(msg)
            }
        }
    })?;

    // 6. For OIDC sources: derive implicit billets via ImplicitBilletMapper
    let implicit_result = match &identity {
        AuthenticatedIdentity::Oidc(oidc) => {
            state
                .implicit_billet_mapper
                .derive_billets(&oidc.idp_prefix, &oidc.claims)
        }
        _ => Default::default(),
    };

    // 7. Assemble final token billets: strip reserved prefixes from Cedar billets,
    //    union with implicit token billets
    let reserved_prefixes = state.implicit_billet_mapper.reserved_prefixes();
    let final_billets = assemble_token_billets(
        &resolution.billets,
        &implicit_result,
        reserved_prefixes,
    );

    // 8. Build the identity claim for the JWT
    let identity_claim = build_identity_claim(&identity);

    // 9. Issue JWT with identity claim and source-formatted sub
    let issue_req = IssueRequest {
        spiffe_id: subject.clone(),
        audience: audience.clone(),
        billets: final_billets.clone(),
        identity_claim: Some(identity_claim),
        subject_override: Some(subject.clone()),
    };

    let issue_resp = state.issuer.issue(issue_req).await.map_err(|e| {
        DomainError::service_unavailable(e.to_string())
    })?;

    // 10. (Optional) Issue certificate if CSR provided
    let certificate_chain = if let Some(csr_b64) = form.csr {
        let csr_der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &csr_b64,
        )
        .map_err(|e| DomainError::invalid_request(format!("invalid CSR base64: {e}")))?;

        let cert_req = CertIssueRequest {
            csr_der,
            spiffe_id: subject.clone(),
            billets: final_billets.clone(),
        };

        let cert_resp = state.authority.issue(cert_req).await.map_err(|e| {
            DomainError::invalid_request(e.to_string())
        })?;

        Some(String::from_utf8_lossy(&cert_resp.chain_pem).to_string())
    } else {
        None
    };

    // 11. Audit log success
    let actor = AuditActor {
        subject: subject.clone(),
        source_type: source_type.clone(),
    };
    let details = TokenExchangeDetails {
        cedar_billets: resolution.billets.clone(),
        implicit_billets: implicit_result.all_billets.clone(),
        audience: audience.clone(),
        jti: Some(issue_resp.jti.clone()),
        identity_details: build_identity_audit_details(&identity),
    };
    state.audit_service.emit(
        AuditEnvelope::token_exchange_success(&request_id, actor, details)
    );

    // 12. Build response
    let response = TokenExchangeResponse {
        access_token: issue_resp.access_token,
        issued_token_type: issue_resp.issued_token_type,
        token_type: issue_resp.token_type,
        expires_in: issue_resp.expires_in,
        certificate_chain,
    };

    Ok(axum::Json(response))
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/// Maps an IdentityError to the appropriate DomainError HTTP response.
fn identity_error_to_domain_error(e: IdentityError) -> DomainError {
    match e {
        IdentityError::UnknownTokenType(_) => DomainError::invalid_request(e.to_string()),
        IdentityError::IssuerNotFound(_)
        | IdentityError::InvalidSignature(_)
        | IdentityError::TokenExpired
        | IdentityError::AudienceMismatch(_)
        | IdentityError::InvalidPresignedUrl(_)
        | IdentityError::UpstreamCallFailed(_)
        | IdentityError::NotAllowed(_)
        | IdentityError::MissingClaim(_) => DomainError::invalid_token(e.to_string()),
        IdentityError::KeysStale(_) => DomainError::service_unavailable(e.to_string()),
    }
}

/// Derives the source_type string from a subject_token_type URI.
/// Used for audit logging when identity validation fails before we have an AuthenticatedIdentity.
fn source_type_from_token_type(token_type: &str) -> String {
    match token_type {
        "urn:ietf:params:oauth:token-type:jwt" => "spire".to_string(),
        "urn:quartermaster:token-type:oidc" => "oidc".to_string(),
        "urn:quartermaster:token-type:aws-presigned-sts" => "aws-sts".to_string(),
        "urn:quartermaster:token-type:gcp-identity" => "gcp".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Builds a ResolverInput from an AuthenticatedIdentity.
///
/// For SPIRE, uses the SPIFFE ID and claims directly (backward-compatible).
/// For other sources, uses the formatted subject as the key with minimal defaults.
fn build_resolver_input(
    identity: &AuthenticatedIdentity,
    subject: &str,
    audience: &str,
) -> ResolverInput {
    match identity {
        AuthenticatedIdentity::Spire(spire) => ResolverInput {
            spiffe_id: spire.spiffe_id.clone(),
            trust_domain: spire.trust_domain.clone(),
            environment: spire.environment.clone(),
            region: spire.region.clone(),
            audience: audience.to_string(),
            request_time: chrono::Utc::now(),
            source_cloud: String::new(),
            selectors: vec![],
        },
        AuthenticatedIdentity::AwsSts(_) => ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: audience.to_string(),
            request_time: chrono::Utc::now(),
            source_cloud: "aws".to_string(),
            selectors: vec![],
        },
        AuthenticatedIdentity::Gcp(_) => ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: audience.to_string(),
            request_time: chrono::Utc::now(),
            source_cloud: "gcp".to_string(),
            selectors: vec![],
        },
        AuthenticatedIdentity::Oidc(_) => ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: audience.to_string(),
            request_time: chrono::Utc::now(),
            source_cloud: String::new(),
            selectors: vec![],
        },
    }
}

/// Builds IdentityAuditDetails from an AuthenticatedIdentity for audit logging.
fn build_identity_audit_details(identity: &AuthenticatedIdentity) -> IdentityAuditDetails {
    match identity {
        AuthenticatedIdentity::Spire(spire) => IdentityAuditDetails::Spire {
            spiffe_id: spire.spiffe_id.clone(),
        },
        AuthenticatedIdentity::Oidc(oidc) => IdentityAuditDetails::Oidc {
            email: oidc.email.clone(),
            idp_prefix: oidc.idp_prefix.clone(),
            groups: oidc
                .claims
                .values()
                .flatten()
                .cloned()
                .collect(),
        },
        AuthenticatedIdentity::AwsSts(aws) => IdentityAuditDetails::AwsSts {
            account_id: aws.account_id.clone(),
            role_arn: aws.role_arn.clone(),
        },
        AuthenticatedIdentity::Gcp(gcp) => IdentityAuditDetails::Gcp {
            project_id: gcp.project_id.clone(),
            service_account_email: gcp.email.clone(),
        },
    }
}
