// HTTP server setup (axum), route registration

pub mod middleware;
pub mod tls;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::cedar::LocalAuthorizer;
use crate::datastore::DataStore;
use crate::domain::admin::authenticator::Authenticator;
use crate::domain::admin::billets::BilletCrudService;
use crate::domain::admin::policies::PolicyCrudService;
use crate::domain::audit::AuditService;
use crate::domain::billet::Resolver;
use crate::domain::cache::Cache;
use crate::domain::cert::Authority;
use crate::domain::identity::dispatcher::IdentityDispatcher;
use crate::domain::identity::entity::MultiSourceEntityBuilder;
use crate::domain::identity::implicit::ImplicitBilletMapper;
use crate::domain::identity::jwks::JwksManager;
use crate::domain::identity::mtls::MtlsValidator;
use crate::domain::identity::path_pattern::PathPatternMatcher;
use crate::domain::ratelimit::Limiter;
use crate::domain::token::Issuer;
use crate::keymanager::KeyManager;
use crate::signing::SigningManager;
use crate::sync::PolicySyncService;

use crate::handler;

/// Shared application state holding all domain components.
/// Passed to handlers via `axum::extract::State<Arc<AppState>>`.
pub struct AppState {
    pub resolver: Arc<dyn Resolver>,
    pub issuer: Arc<dyn Issuer>,
    pub authority: Arc<dyn Authority>,
    pub cache: Arc<dyn Cache>,
    pub rate_limiter: Arc<dyn Limiter>,
    pub audit_service: AuditService,
    pub signing_manager: Arc<dyn SigningManager>,
    pub signing_key_manager: Arc<dyn KeyManager>,
    pub policy_sync: Arc<PolicySyncService>,
    pub data_store: Arc<dyn DataStore>,
    pub local_authorizer: Arc<dyn LocalAuthorizer>,
    pub admin_authenticator: Arc<dyn Authenticator>,
    pub billet_crud_service: Arc<BilletCrudService>,
    pub policy_crud_service: Arc<PolicyCrudService>,
    pub issuer_url: String,
    pub algorithm: String,
    /// Multi-source identity dispatcher (routes by subject_token_type).
    pub identity_dispatcher: Arc<dyn IdentityDispatcher>,
    /// Entity builder for constructing Cedar principal entities from any identity source.
    pub entity_builder: Arc<MultiSourceEntityBuilder>,
    /// Implicit billet mapper for OIDC sources.
    pub implicit_billet_mapper: Arc<ImplicitBilletMapper>,
    /// JWKS manager for all JWT-based identity sources (OIDC IdPs, GCP).
    /// `None` when no JWT-based sources (OIDC, GCP) are configured.
    /// Used for health checks and monitoring of key freshness.
    pub jwks_manager: Option<Arc<JwksManager>>,
    /// mTLS client certificate validator.
    /// `None` when:
    /// - `[identity.spire]` is not configured, OR
    /// - `[identity.spire].x509_bundle_path` is absent, OR
    /// - `[server.tls]` is absent
    pub mtls_validator: Option<Arc<MtlsValidator>>,
    /// Path pattern matcher for extracting attributes from SPIFFE ID paths.
    /// `Some` when `[[identity.spire.path_patterns]]` is configured (path-pattern mode).
    /// `None` when using legacy SPIRE API enrichment or no-op mode.
    pub path_pattern_matcher: Option<Arc<PathPatternMatcher>>,
}

/// Builds the data-plane router, conditionally including admin routes.
///
/// When `include_admin` is `true`, admin routes (`/admin/*`) are mounted on this router.
/// When `false`, only data-plane routes are included (admin routes are served on a separate listener).
pub fn build_main_router(state: Arc<AppState>, include_admin: bool) -> Router {
    let mut app = Router::new()
        // OpenAPI spec (unauthenticated)
        .route("/openapi.json", get(crate::openapi::openapi_json))
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
        .route("/billets/me", post(handler::billets_discovery::billet_discovery));

    if include_admin {
        app = app
            .route(
                "/admin/billets",
                post(handler::admin_billets::create_billet)
                    .get(handler::admin_billets::list_billets),
            )
            .route(
                "/admin/billets/{name}",
                get(handler::admin_billets::get_billet)
                    .put(handler::admin_billets::update_billet)
                    .delete(handler::admin_billets::delete_billet),
            )
            .route(
                "/admin/billets/{name}/policies",
                post(handler::admin_billets::create_policy)
                    .get(handler::admin_billets::list_policies),
            )
            .route(
                "/admin/billets/{name}/policies/{id}",
                get(handler::admin_billets::get_policy)
                    .put(handler::admin_billets::update_policy)
                    .delete(handler::admin_billets::delete_policy),
            );
    }

    let app = app.with_state(state);
    middleware::apply_middleware(app)
}

/// Builds the admin-only router with `/admin/*` routes and middleware.
///
/// Used when the admin listener is on a separate address.
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    let app = Router::new()
        .route(
            "/admin/billets",
            post(handler::admin_billets::create_billet)
                .get(handler::admin_billets::list_billets),
        )
        .route(
            "/admin/billets/{name}",
            get(handler::admin_billets::get_billet)
                .put(handler::admin_billets::update_billet)
                .delete(handler::admin_billets::delete_billet),
        )
        .route(
            "/admin/billets/{name}/policies",
            post(handler::admin_billets::create_policy)
                .get(handler::admin_billets::list_policies),
        )
        .route(
            "/admin/billets/{name}/policies/{id}",
            get(handler::admin_billets::get_policy)
                .put(handler::admin_billets::update_policy)
                .delete(handler::admin_billets::delete_policy),
        )
        .with_state(state);

    middleware::apply_middleware(app)
}

/// Builds the axum Router with all routes and middleware applied.
///
/// This is a backward-compatible wrapper that includes both data-plane and admin routes
/// on a single router. Equivalent to `build_main_router(state, true)`.
pub fn build_router(state: Arc<AppState>) -> Router {
    build_main_router(state, true)
}
