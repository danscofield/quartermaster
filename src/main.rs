use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use quartermaster::cedar::CedarAuthorizer;
use quartermaster::config::Config;
use quartermaster::domain::admin::authenticator::AdminAuthenticatorImpl;
use quartermaster::domain::admin::billets::BilletCrudService;
use quartermaster::domain::admin::policies::PolicyCrudService;
use quartermaster::domain::audit::TracingAuditLogger;
use quartermaster::domain::billet::entity_builder::EntityBuilder;
use quartermaster::domain::billet::selector::SpireSelectorEnricher;
use quartermaster::domain::billet::BilletResolverImpl;
use quartermaster::domain::cache::memory::InMemoryCache;
use quartermaster::domain::cert::LocalAuthority;
use quartermaster::domain::ratelimit::InMemoryLimiter;
use quartermaster::domain::svid::SpireValidator;
use quartermaster::domain::token::Es256Issuer;
use quartermaster::dynamo::AwsDynamoClient;
use quartermaster::server::{self, AppState};
use quartermaster::signing::static_key::StaticKeyManager;
use quartermaster::spireapi::HttpSpireApiClient;
use quartermaster::sync::PolicySyncService;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!("Quartermaster starting");

    // Load configuration
    let config = Config::load().expect("failed to load configuration");
    tracing::info!(issuer = %config.issuer, "configuration loaded");

    // Initialize SigningManager from PEM file
    let signing_manager: Arc<dyn quartermaster::signing::SigningManager> = Arc::new(
        StaticKeyManager::from_pem_file(&config.signing.key_path)
            .expect("failed to load signing key"),
    );

    // Initialize SVID Validator from SPIRE trust bundle
    let trust_bundle_json = std::fs::read_to_string(&config.spire.trust_bundle_path)
        .expect("failed to read SPIRE trust bundle");
    let trust_bundle_keys = SpireValidator::parse_jwks(&trust_bundle_json)
        .expect("failed to parse SPIRE trust bundle JWKS");
    let validator: Arc<dyn quartermaster::domain::svid::Validator> = Arc::new(
        SpireValidator::new(
            trust_bundle_keys,
            config.spire.trust_domain.clone(),
            config.issuer.clone(),
        ),
    );

    // Initialize LocalAuthority from CA PEM files
    let ca_key_pem = std::fs::read_to_string(&config.ca.key_path)
        .expect("failed to read CA key");
    let ca_cert_pem = std::fs::read_to_string(&config.ca.cert_path)
        .expect("failed to read CA certificate");
    let authority: Arc<dyn quartermaster::domain::cert::Authority> = Arc::new(
        LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(config.ca.ttl_secs))
            .expect("failed to initialize CA"),
    );

    // Initialize DynamoClient with AWS config
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.dynamo.region.clone()))
        .load()
        .await;
    let dynamo_client: Arc<dyn quartermaster::dynamo::DynamoClient> = Arc::new(
        AwsDynamoClient::new(
            &aws_config,
            config.dynamo.policies_table.clone(),
            config.dynamo.billets_table.clone(),
        ),
    );

    // Initialize PolicySyncService and start background sync
    let policy_sync = Arc::new(PolicySyncService::new(
        Arc::clone(&dynamo_client),
        config.dynamo.policy_sync_interval_secs,
    ));
    let policy_sync_handle = Arc::clone(&policy_sync).start();

    // Wait briefly for initial sync, but don't block indefinitely
    // (health endpoint will report 503 if not initialized)
    for _ in 0..50 {
        if policy_sync.is_initialized().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if policy_sync.is_initialized().await {
        tracing::info!("initial policy sync completed");
    } else {
        tracing::warn!("initial policy sync not yet complete, service will report degraded health");
    }

    // Initialize CedarAuthorizer with PolicySyncService's policy_set_handle
    let local_authorizer: Arc<dyn quartermaster::cedar::LocalAuthorizer> = Arc::new(
        CedarAuthorizer::new(policy_sync.policy_set_handle()),
    );

    // Initialize InMemoryCache
    let cache: Arc<dyn quartermaster::domain::cache::Cache> =
        Arc::new(InMemoryCache::new());

    // Initialize InMemoryLimiter
    let rate_limiter: Arc<dyn quartermaster::domain::ratelimit::Limiter> = Arc::new(
        InMemoryLimiter::with_background_cleanup(
            config.rate.requests_per_minute,
            Duration::from_secs(60),
        ),
    );

    // Initialize TracingAuditLogger
    let audit_logger: Arc<dyn quartermaster::domain::audit::AuditLogger> =
        Arc::new(TracingAuditLogger::new());

    // Initialize HttpSpireApiClient
    let spire_api_client: Arc<dyn quartermaster::spireapi::SpireApiClient> =
        Arc::new(HttpSpireApiClient::new(
            format!("http://localhost:8081"), // TODO: make configurable
        ));

    // Initialize SpireSelectorEnricher
    let selector_enricher: Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher> =
        Arc::new(SpireSelectorEnricher::new(spire_api_client));

    // Initialize EntityBuilder
    let entity_builder = EntityBuilder::new();

    // Initialize BilletResolverImpl
    let resolver: Arc<dyn quartermaster::domain::billet::Resolver> = Arc::new(
        BilletResolverImpl::new(
            selector_enricher,
            entity_builder,
            Arc::clone(&local_authorizer),
            Arc::clone(&cache),
            Arc::clone(&policy_sync),
            Duration::from_secs(config.cache.ttl_secs),
        ),
    );

    // Initialize Es256Issuer
    let issuer: Arc<dyn quartermaster::domain::token::Issuer> = Arc::new(Es256Issuer::new(
        Arc::clone(&signing_manager),
        config.issuer.clone(),
        config.token_ttl_secs,
    ));

    // Initialize AdminAuthenticatorImpl
    let admin_authenticator: Arc<dyn quartermaster::domain::admin::authenticator::Authenticator> =
        Arc::new(AdminAuthenticatorImpl::new(
            Arc::clone(&signing_manager),
            Arc::clone(&local_authorizer),
            config.issuer.clone(),
        ));

    // Initialize BilletCrudService
    let billet_crud_service = Arc::new(BilletCrudService::new(
        Arc::clone(&dynamo_client),
        Arc::clone(&policy_sync),
    ));

    // Initialize PolicyCrudService
    let policy_crud_service = Arc::new(PolicyCrudService::new(Arc::clone(&dynamo_client)));

    // Build AppState
    let app_state = Arc::new(AppState {
        validator,
        resolver,
        issuer,
        authority,
        cache,
        rate_limiter,
        audit_logger,
        signing_manager,
        policy_sync,
        dynamo_client,
        local_authorizer,
        admin_authenticator,
        billet_crud_service,
        policy_crud_service,
        issuer_url: config.issuer.clone(),
        algorithm: config.signing.algorithm.clone(),
    });

    // Build router
    let router = server::build_router(app_state);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!(addr = %addr, "starting HTTP server");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, router)
        .await
        .expect("server error");

    // Clean up background tasks (unreachable in practice since serve blocks)
    policy_sync_handle.abort();
}
