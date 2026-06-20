// OpenAPI spec generation via utoipa

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::domain::admin::billets::{BilletWithPolicies, PolicySummary};
use crate::handler;

/// Aggregates all OpenAPI paths, schemas, and security schemes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Quartermaster",
        version = "0.1.0",
        description = "Workload identity federation broker"
    ),
    paths(
        handler::token::token_exchange,
        handler::billets_discovery::billet_discovery,
        handler::billets::get_billet,
        handler::oidc::openid_configuration,
        handler::jwks::jwks,
        handler::ca::ca_chain,
        handler::health::healthz,
        handler::admin_billets::create_billet,
        handler::admin_billets::list_billets,
        handler::admin_billets::get_billet,
        handler::admin_billets::update_billet,
        handler::admin_billets::delete_billet,
        handler::admin_billets::create_policy,
        handler::admin_billets::list_policies,
        handler::admin_billets::get_policy,
        handler::admin_billets::update_policy,
        handler::admin_billets::delete_policy,
    ),
    components(
        schemas(
            handler::token::TokenExchangeForm,
            handler::token::TokenExchangeResponse,
            handler::billets_discovery::BilletDiscoveryForm,
            handler::billets_discovery::BilletDiscoveryResponse,
            handler::billets::BilletMetadataResponse,
            handler::admin_billets::AdminBilletMetadataResponse,
            BilletWithPolicies,
            PolicySummary,
            handler::admin_billets::CreateBilletRequest,
            handler::admin_billets::UpdateBilletRequest,
            handler::admin_billets::CreatePolicyRequest,
            handler::admin_billets::UpdatePolicyRequest,
            handler::admin_billets::PolicyResponse,
            crate::domain::ErrorBody,
            handler::health::HealthResponse,
            handler::health::HealthChecks,
            crate::oidc::DiscoveryDocument,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "token-exchange", description = "RFC 8693 token exchange"),
        (name = "discovery", description = "OIDC discovery, JWKS, CA chain, billet lookup"),
        (name = "admin-billets", description = "Billet CRUD (admin control plane)"),
        (name = "admin-policies", description = "Policy CRUD (admin control plane)"),
        (name = "system", description = "Health and operational endpoints"),
    )
)]
pub struct ApiDoc;

/// Adds BearerAuth and MutualTLS security schemes.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "BearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "MutualTLS",
                SecurityScheme::MutualTls {
                    description: Some("mTLS client certificate".to_string()),
                    extensions: Default::default(),
                },
            );
        }
    }
}

/// GET /openapi.json — returns the generated OpenAPI spec.
pub async fn openapi_json() -> impl IntoResponse {
    let spec = ApiDoc::openapi();
    match spec.to_pretty_json() {
        Ok(json) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
