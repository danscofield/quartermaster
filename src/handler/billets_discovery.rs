// POST /billets/me handler — discover entitled billets without issuing a token.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Extension, Form};
use serde::{Deserialize, Serialize};

use crate::domain::audit::IdentityAuditDetails;
use crate::domain::audit::schema::{AuditActor, AuditEnvelope, TokenExchangeDetails};
use crate::domain::billet::BilletError;
use crate::domain::identity::entity::{source_type_for_identity, source_type_for_spire_identity};
use crate::domain::identity::implicit::assemble_token_billets;
use crate::domain::identity::subject::format_subject;
use crate::domain::identity::{AuthenticatedIdentity, IdentityError, SpireAuthSource};
use crate::domain::{DomainError, ErrorCode};
use crate::server::AppState;
use crate::server::middleware::ClientCertificate;

/// Form body for the billet discovery request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BilletDiscoveryForm {
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
}

/// JSON response for billet discovery.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BilletDiscoveryResponse {
    pub billets: Vec<String>,
    pub implicit_billets: Vec<String>,
    pub cedar_billets: Vec<String>,
}

/// POST /billets/me — discover entitled billets without issuing a token.
///
/// Performs steps 1–7 of the token exchange flow (validate identity → rate limit →
/// resolve billets → implicit mapping → assemble), then returns the resolution
/// directly as a JSON response.
///
/// Returns 200 with empty arrays when the caller has no entitled billets (graceful).
#[utoipa::path(
    post,
    path = "/billets/me",
    tag = "discovery",
    request_body(content = BilletDiscoveryForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Discovery result", body = BilletDiscoveryResponse),
        (status = 400, description = "Bad request", body = crate::domain::ErrorBody),
        (status = 401, description = "Unauthorized", body = crate::domain::ErrorBody),
    ),
    security(("MutualTLS" = []))
)]
pub async fn billet_discovery(
    State(state): State<Arc<AppState>>,
    Extension(client_cert): Extension<ClientCertificate>,
    headers: axum::http::HeaderMap,
    Form(form): Form<BilletDiscoveryForm>,
) -> Result<impl IntoResponse, DomainError> {
    // Extract request ID from middleware-generated header
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // 1. Unified identity resolution with precedence logic:
    //    - If subject_token present → use token dispatch (existing path)
    //    - If absent, try mTLS identity from client certificate
    //    - If neither available → return 400
    let (identity, auth_source) = if let Some(subject_token) = form.subject_token {
        // Explicit token always takes precedence
        let subject_token_type = form.subject_token_type.ok_or_else(|| {
            DomainError::invalid_request("subject_token_type is required when subject_token is provided")
        })?;

        let id = state
            .identity_dispatcher
            .validate(&subject_token, &subject_token_type)
            .await
            .map_err(|e| {
                let actor = AuditActor {
                    subject: String::new(),
                    source_type: source_type_from_token_type(&subject_token_type),
                };
                let details = TokenExchangeDetails {
                    cedar_billets: vec![],
                    implicit_billets: vec![],
                    audience: String::new(),
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

        // Determine auth source based on the identity type
        let source = match &id {
            AuthenticatedIdentity::Spire(_) => SpireAuthSource::JwtSvid,
            _ => SpireAuthSource::JwtSvid, // Non-SPIRE identities don't use SpireAuthSource, but we track it for uniformity
        };
        (id, source)
    } else if let Some(mtls_identity) = extract_mtls_identity(&client_cert, &state) {
        (AuthenticatedIdentity::Spire(mtls_identity), SpireAuthSource::MtlsCert)
    } else {
        return Err(DomainError::invalid_request(
            "subject_token is required when no client certificate is presented",
        ));
    };

    // 2. Format subject and determine source type
    let subject = format_subject(&identity);
    let _source_type = match &identity {
        AuthenticatedIdentity::Spire(_) => source_type_for_spire_identity(auth_source).to_string(),
        _ => source_type_for_identity(&identity).to_string(),
    };

    // 4. Rate limit check (keyed by formatted subject)
    let allowed = state.rate_limiter.allow(&subject).await.map_err(|e| {
        DomainError::new(ErrorCode::ServiceUnavailable, e.to_string())
    })?;

    if !allowed {
        return Err(DomainError::rate_limited("rate limit exceeded"));
    }

    // 5. Resolve billets via Cedar evaluation
    //    Use a dummy audience since discovery doesn't target a specific audience.
    let resolver_input = build_resolver_input(&identity, &subject);

    let resolution = match state.resolver.resolve(resolver_input).await {
        Ok(res) => res,
        Err(BilletError::NoBilletsResolved) => {
            // Discovery is graceful — return 200 with empty arrays
            return Ok(axum::Json(BilletDiscoveryResponse {
                billets: vec![],
                implicit_billets: vec![],
                cedar_billets: vec![],
            }));
        }
        Err(BilletError::PolicySetNotInitialized) => {
            return Err(DomainError::service_unavailable("policy set not initialized"));
        }
        Err(BilletError::InternalError(msg)) => {
            return Err(DomainError::service_unavailable(msg));
        }
    };

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

    // Return discovery response with all three fields
    let response = BilletDiscoveryResponse {
        billets: final_billets,
        implicit_billets: implicit_result.token_billets,
        cedar_billets: resolution.billets,
    };

    Ok(axum::Json(response))
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/// Attempts to extract a SPIRE identity from the client certificate presented during TLS.
///
/// Returns `Some(SpireIdentity)` if:
/// - The `MtlsValidator` is configured in AppState
/// - A client certificate was presented (DER bytes present)
/// - The certificate validates against the trust bundle and contains a valid SPIFFE URI SAN
///
/// Returns `None` if any of those conditions are not met (silent fallback).
fn extract_mtls_identity(
    client_cert: &ClientCertificate,
    state: &AppState,
) -> Option<crate::domain::identity::SpireIdentity> {
    let cert_der = client_cert.0.as_ref()?;
    let validator = state.mtls_validator.as_ref()?;
    validator.validate(cert_der)
}

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
fn source_type_from_token_type(token_type: &str) -> String {
    match token_type {
        "urn:ietf:params:oauth:token-type:jwt" => "spire".to_string(),
        "urn:quartermaster:token-type:oidc" => "oidc".to_string(),
        "urn:quartermaster:token-type:aws-presigned-sts" => "aws-sts".to_string(),
        "urn:quartermaster:token-type:gcp-identity" => "gcp".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Builds a ResolverInput from an AuthenticatedIdentity for discovery.
///
/// Discovery does not have a specific audience, so we use an empty string.
fn build_resolver_input(
    identity: &AuthenticatedIdentity,
    subject: &str,
) -> crate::domain::billet::ResolverInput {
    match identity {
        AuthenticatedIdentity::Spire(spire) => crate::domain::billet::ResolverInput {
            spiffe_id: spire.spiffe_id.clone(),
            trust_domain: spire.trust_domain.clone(),
            environment: spire.environment.clone(),
            region: spire.region.clone(),
            audience: String::new(),
            request_time: chrono::Utc::now(),
            source_cloud: String::new(),
        },
        AuthenticatedIdentity::AwsSts(_) => crate::domain::billet::ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: String::new(),
            request_time: chrono::Utc::now(),
            source_cloud: "aws".to_string(),
        },
        AuthenticatedIdentity::Gcp(_) => crate::domain::billet::ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: String::new(),
            request_time: chrono::Utc::now(),
            source_cloud: "gcp".to_string(),
        },
        AuthenticatedIdentity::Oidc(_) => crate::domain::billet::ResolverInput {
            spiffe_id: subject.to_string(),
            trust_domain: String::new(),
            environment: String::new(),
            region: String::new(),
            audience: String::new(),
            request_time: chrono::Utc::now(),
            source_cloud: String::new(),
        },
    }
}
