// HTTP server setup (axum), route registration

pub mod middleware;

use std::sync::Arc;

use axum::routing::{get, post, put};
use axum::Router;

use crate::cedar::LocalAuthorizer;
use crate::domain::admin::authenticator::Authenticator;
use crate::domain::admin::billets::BilletCrudService;
use crate::domain::admin::policies::PolicyCrudService;
use crate::domain::audit::AuditLogger;
use crate::domain::billet::Resolver;
use crate::domain::cache::Cache;
use crate::domain::cert::Authority;
use crate::domain::ratelimit::Limiter;
use crate::domain::svid::Validator;
use crate::domain::token::Issuer;
use crate::dynamo::DynamoClient;
use crate::signing::SigningManager;
use crate::sync::PolicySyncService;

use crate::handler;

/// Shared application state holding all domain components.
/// Passed to handlers via `axum::extract::State<Arc<AppState>>`.
pub struct AppState {
    pub validator: Arc<dyn Validator>,
    pub resolver: Arc<dyn Resolver>,
    pub issuer: Arc<dyn Issuer>,
    pub authority: Arc<dyn Authority>,
    pub cache: Arc<dyn Cache>,
    pub rate_limiter: Arc<dyn Limiter>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub signing_manager: Arc<dyn SigningManager>,
    pub policy_sync: Arc<PolicySyncService>,
    pub dynamo_client: Arc<dyn DynamoClient>,
    pub local_authorizer: Arc<dyn LocalAuthorizer>,
    pub admin_authenticator: Arc<dyn Authenticator>,
    pub billet_crud_service: Arc<BilletCrudService>,
    pub policy_crud_service: Arc<PolicyCrudService>,
    pub issuer_url: String,
    pub algorithm: String,
}

/// Builds the axum Router with all routes and middleware applied.
pub fn build_router(state: Arc<AppState>) -> Router {
    let app = Router::new()
        // Data-plane routes
        .route("/token", post(handler::token::token_exchange))
        .route(
            "/.well-known/openid-configuration",
            get(handler::oidc::openid_configuration),
        )
        .route("/jwks.json", get(handler::jwks::jwks))
        .route("/ca/chain.pem", get(handler::ca::ca_chain))
        .route("/healthz", get(handler::health::healthz))
        .route("/billets/{name}", get(handler::billets::get_billet))
        // Admin routes
        .route(
            "/admin/billets",
            post(handler::admin_billets::create_billet)
                .get(handler::admin_billets::list_billets),
        )
        .route(
            "/admin/billets/{name}",
            get(handler::admin_billets::get_billet)
                .delete(handler::admin_billets::delete_billet),
        )
        .route("/admin/policies", post(handler::admin_policies::create_policy))
        .route(
            "/admin/policies/{id}",
            put(handler::admin_policies::update_policy)
                .delete(handler::admin_policies::delete_policy),
        )
        .with_state(state);

    middleware::apply_middleware(app)
}
