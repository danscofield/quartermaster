use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use quartermaster::cedar::CedarAuthorizer;
use quartermaster::config::Config;
use quartermaster::config::identity::IdentityConfig;
use quartermaster::domain::admin::authenticator::AdminAuthenticatorImpl;
use quartermaster::domain::admin::billets::BilletCrudService;
use quartermaster::domain::admin::policies::PolicyCrudService;
use quartermaster::domain::audit::config::build_sinks;
use quartermaster::domain::audit::AuditService;
use quartermaster::domain::billet::entity_builder::EntityBuilder;
use quartermaster::domain::billet::selector::SpireSelectorEnricher;
use quartermaster::domain::billet::BilletResolverImpl;
use quartermaster::domain::cache::memory::InMemoryCache;
use quartermaster::domain::cert::LocalAuthority;
use quartermaster::domain::identity::dispatcher::DefaultIdentityDispatcher;
use quartermaster::domain::identity::entity::MultiSourceEntityBuilder;
use quartermaster::domain::identity::implicit::ImplicitBilletMapper;
use quartermaster::domain::identity::jwks::JwksManager;
use quartermaster::domain::ratelimit::InMemoryLimiter;
use quartermaster::domain::svid::SpireValidator;
use quartermaster::domain::token::Es256Issuer;
use quartermaster::server::{self, AppState};
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

    // ─── Build DataStore ───────────────────────────────────────────────────────
    // If [datastore] section is present, use the factory; otherwise fall back to legacy
    // [dynamo] section, creating a DynamoDataStore.
    let data_store: Arc<dyn quartermaster::datastore::DataStore> = if let Some(ref ds_config) =
        config.datastore
    {
        quartermaster::datastore::factory::build_datastore(ds_config)
            .await
            .expect("failed to build datastore from [datastore] config")
    } else {
        // Legacy fallback: build DynamoDataStore from [dynamo] section
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.dynamo.region.clone()))
            .load()
            .await;
        Arc::new(quartermaster::datastore::dynamodb::DynamoDataStore::new(
            &quartermaster::config::backends::DynamoDbConfig {
                region: config.dynamo.region.clone(),
                billets_table: config.dynamo.billets_table.clone(),
                policies_table: config.dynamo.policies_table.clone(),
            },
            &aws_config,
        ))
    };

    // ─── Build KeyManager for signing ─────────────────────────────────────────
    // If [signing_backend] section is present, use the factory; otherwise fall back to
    // legacy [signing] section, creating a MemoryKeyManager from the PEM key.
    let signing_key_manager: Arc<dyn quartermaster::keymanager::KeyManager> =
        if let Some(ref sb_config) = config.signing_backend {
            quartermaster::keymanager::factory::build_key_manager(
                sb_config,
                Arc::clone(&data_store),
                "signing",
            )
            .await
            .expect("failed to build signing key manager from [signing_backend] config")
        } else {
            // Legacy fallback: build MemoryKeyManager from [signing] section
            let mem_config = quartermaster::config::backends::MemorySigningConfig {
                key_path: config.signing.key_path.to_str().unwrap_or("").to_string(),
            };
            Arc::new(
                quartermaster::keymanager::memory::MemoryKeyManager::new(&mem_config)
                    .expect("failed to load signing key"),
            )
        };

    // Wrap KeyManager in SigningManagerAdapter for backward compatibility
    let signing_manager: Arc<dyn quartermaster::signing::SigningManager> = Arc::new(
        quartermaster::keymanager::SigningManagerAdapter::new(Arc::clone(&signing_key_manager)),
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

    // Bootstrap system billets (idempotent)
    match quartermaster::domain::bootstrap::bootstrap_system_billets(data_store.as_ref()).await {
        Ok(()) => tracing::info!("bootstrap: system billets verified/created"),
        Err(e) => tracing::warn!(error = %e, "bootstrap: failed to verify/create system billets, continuing"),
    }

    // Initialize AuditService (must be created before PolicySyncService)
    let audit_config = config.audit.clone().unwrap_or_default();
    let sinks = build_sinks(&audit_config).await;
    let audit_service = AuditService::new(sinks, audit_config.buffer_capacity);

    // Initialize PolicySyncService and start background sync
    let policy_sync = Arc::new(PolicySyncService::new(
        Arc::clone(&data_store),
        config.dynamo.policy_sync_interval_secs,
        audit_service.clone(),
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
        CedarAuthorizer::new(policy_sync.policy_set_handle(), Arc::clone(&policy_sync)),
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
        Arc::clone(&data_store),
    ));

    // Initialize PolicyCrudService
    let policy_crud_service = Arc::new(PolicyCrudService::new(
        Arc::clone(&data_store),
        config.system_billets.clone(),
    ));

    // ─── Multi-Source Identity Initialization ──────────────────────────────────
    //
    // Initialization flow (future-proof for full IdentityConfig):
    // 1. Parse IdentityConfig from the app config (when available)
    // 2. If SPIRE configured: create SPIRE validator for dispatcher
    // 3. If OIDC sources configured: create JwksManager, create DefaultOidcValidator
    // 4. If AWS STS enabled: create DefaultAwsStsValidator
    // 5. If GCP enabled: ensure JwksManager includes Google JWKS source, create DefaultGcpValidator
    // 6. Create DefaultIdentityDispatcher with all configured validators
    // 7. Create MultiSourceEntityBuilder
    // 8. Create ImplicitBilletMapper from OIDC sources
    //
    // Currently: SPIRE is the only configured source. Other validators (OIDC, AWS STS, GCP)
    // will be wired when IdentityConfig is added to the main Config file parsing.

    // Initialize IdentityDispatcher with the SPIRE validator.
    // SPIRE initialization is conditional: if config.spire trust bundle is available, use it.
    // Other validators (OIDC, AWS STS, GCP) will be configured via IdentityConfig.
    let identity_dispatcher: Arc<dyn quartermaster::domain::identity::dispatcher::IdentityDispatcher> =
        Arc::new(DefaultIdentityDispatcher::new(
            Some(Box::new(SpireValidator::new(
                SpireValidator::parse_jwks(&trust_bundle_json)
                    .expect("failed to parse SPIRE trust bundle JWKS for dispatcher"),
                config.spire.trust_domain.clone(),
                config.issuer.clone(),
            ))),
            None, // OIDC validator — configured via IdentityConfig
            None, // AWS STS validator — configured via IdentityConfig
            None, // GCP validator — configured via IdentityConfig
        ));

    // Initialize JwksManager for JWT-based identity sources (OIDC IdPs, GCP).
    // Currently no OIDC/GCP sources are configured in the main Config, so we build
    // from an empty IdentityConfig. When IdentityConfig is wired into Config parsing,
    // this will use the actual configured sources and start background refresh tasks.
    let jwks_manager: Option<Arc<JwksManager>> = {
        let identity_config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: None,
            gcp: None,
        };
        // Only create JwksManager if there are JWT-based sources that need key management
        if !identity_config.oidc.is_empty() || identity_config.gcp.as_ref().is_some_and(|g| g.enabled) {
            let http_client = reqwest::Client::new();
            let manager = Arc::new(JwksManager::from_config(&identity_config, http_client));
            manager.start_refresh_tasks();
            Some(manager)
        } else {
            None
        }
    };

    // Initialize MultiSourceEntityBuilder
    let multi_source_entity_builder = Arc::new(MultiSourceEntityBuilder::new(EntityBuilder::new()));

    // Initialize ImplicitBilletMapper (empty config until OIDC sources are configured)
    let implicit_billet_mapper = Arc::new(ImplicitBilletMapper::from_config(&[]));

    // Build AppState
    let app_state = Arc::new(AppState {
        validator,
        resolver,
        issuer,
        authority,
        cache,
        rate_limiter,
        audit_service: audit_service.clone(),
        signing_manager,
        signing_key_manager,
        policy_sync,
        data_store,
        local_authorizer,
        admin_authenticator,
        billet_crud_service,
        policy_crud_service,
        issuer_url: config.issuer.clone(),
        algorithm: config.signing.algorithm.clone(),
        identity_dispatcher,
        entity_builder: multi_source_entity_builder,
        implicit_billet_mapper,
        jwks_manager,
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
    audit_service.shutdown(Duration::from_secs(5)).await;
    policy_sync_handle.abort();
}
