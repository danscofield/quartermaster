use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use quartermaster::cedar::CedarAuthorizer;
use quartermaster::config::Config;
use quartermaster::domain::admin::authenticator::AdminAuthenticatorImpl;
use quartermaster::domain::admin::billets::BilletCrudService;
use quartermaster::domain::admin::policies::PolicyCrudService;
use quartermaster::domain::audit::config::build_sinks;
use quartermaster::domain::audit::AuditService;
use quartermaster::domain::billet::entity_builder::EntityBuilder;
use quartermaster::domain::billet::selector::{NoOpSelectorEnricher, SpireSelectorEnricher};
use quartermaster::domain::billet::BilletResolverImpl;
use quartermaster::config::CacheBackend;
use quartermaster::domain::cache::memory::InMemoryCache;
use quartermaster::domain::cache::redis::RedisCache;
use quartermaster::domain::cert::LocalAuthority;
use quartermaster::domain::cert::kms_authority::KmsBackedAuthority;
use quartermaster::domain::identity::aws_sts::DefaultAwsStsValidator;
use quartermaster::domain::identity::dispatcher::DefaultIdentityDispatcher;
use quartermaster::domain::identity::entity::MultiSourceEntityBuilder;
use quartermaster::domain::identity::gcp::DefaultGcpValidator;
use quartermaster::domain::identity::implicit::ImplicitBilletMapper;
use quartermaster::domain::identity::jwks::JwksManager;
use quartermaster::domain::identity::oidc::DefaultOidcValidator;
use quartermaster::domain::ratelimit::InMemoryLimiter;
use quartermaster::domain::svid::SpireValidator;
use quartermaster::domain::token::Es256Issuer;
use quartermaster::server::{self, AppState};
use quartermaster::spireapi::HttpSpireApiClient;
use quartermaster::sync::PolicySyncService;

/// Resolves the policy sync interval with cascading priority:
/// 1. `config.datastore.policy_sync_interval_secs` (if `[datastore]` section is present)
/// 2. `config.dynamo.policy_sync_interval_secs` (if legacy `[dynamo]` section is present)
/// 3. Default: 30 seconds
fn resolve_policy_sync_interval(config: &Config) -> u64 {
    if let Some(ref ds) = config.datastore {
        ds.policy_sync_interval_secs
    } else if let Some(ref dynamo) = config.dynamo {
        dynamo.policy_sync_interval_secs
    } else {
        30
    }
}

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
        let dynamo_config = config.dynamo.as_ref()
            .expect("either [datastore] or [dynamo] section must be present in config");
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(dynamo_config.region.clone()))
            .load()
            .await;
        Arc::new(quartermaster::datastore::dynamodb::DynamoDataStore::new(
            &quartermaster::config::backends::DynamoDbConfig {
                region: dynamo_config.region.clone(),
                billets_table: dynamo_config.billets_table.clone(),
                policies_table: dynamo_config.policies_table.clone(),
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

    // ─── Build Certificate Authority ──────────────────────────────────────────
    // If [ca_backend] section is present, use the factory to build a CA key manager
    // and construct KmsBackedAuthority; otherwise fall back to legacy [ca] section
    // with LocalAuthority.
    let authority: Arc<dyn quartermaster::domain::cert::Authority> =
        if let Some(ref ca_backend_config) = config.ca_backend {
            let ca_key_manager = quartermaster::keymanager::factory::build_key_manager(
                ca_backend_config,
                Arc::clone(&data_store),
                "ca",
            )
            .await
            .expect("failed to build CA key manager");

            let ca_key_pem = std::fs::read_to_string(&config.ca.key_path)
                .expect("failed to read CA key");
            let ca_cert_pem = std::fs::read_to_string(&config.ca.cert_path)
                .expect("failed to read CA certificate");

            Arc::new(
                KmsBackedAuthority::new(
                    ca_key_manager,
                    &ca_key_pem,
                    &ca_cert_pem,
                    Duration::from_secs(config.ca.ttl_secs),
                )
                .expect("failed to initialize KMS-backed CA"),
            )
        } else {
            // Legacy fallback: build LocalAuthority from [ca] section PEM files
            let ca_key_pem = std::fs::read_to_string(&config.ca.key_path)
                .expect("failed to read CA key");
            let ca_cert_pem = std::fs::read_to_string(&config.ca.cert_path)
                .expect("failed to read CA certificate");

            Arc::new(
                LocalAuthority::new(&ca_key_pem, &ca_cert_pem, Duration::from_secs(config.ca.ttl_secs))
                    .expect("failed to initialize CA"),
            )
        };

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
        resolve_policy_sync_interval(&config),
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
        CedarAuthorizer::new(policy_sync.policy_set_handle(), Arc::clone(&policy_sync), config.system_billets.clone()),
    );

    // Initialize cache backend
    let cache: Arc<dyn quartermaster::domain::cache::Cache> = match config.cache.backend {
        CacheBackend::Redis => {
            let redis_url = &config.redis.as_ref().unwrap().url;
            Arc::new(
                RedisCache::new(redis_url)
                    .await
                    .expect("failed to connect to Redis"),
            )
        }
        CacheBackend::Memory => Arc::new(InMemoryCache::new()),
    };

    // Initialize InMemoryLimiter
    let rate_limiter: Arc<dyn quartermaster::domain::ratelimit::Limiter> = Arc::new(
        InMemoryLimiter::with_background_cleanup(
            config.rate.requests_per_minute,
            Duration::from_secs(60),
        ),
    );

    // Initialize SelectorEnricher with mode selection based on path_patterns configuration.
    //
    // Mode selection logic:
    // | path_patterns | server_addr | Behavior                                    |
    // |---------------|-------------|---------------------------------------------|
    // | Non-empty     | Any         | PathPatternMatcher (no API calls)           |
    // | Empty/absent  | Present     | SpireSelectorEnricher (API calls)           |
    // | Empty/absent  | Absent      | NoOpSelectorEnricher (spiffe_id + trust_domain only) |
    let (selector_enricher, path_pattern_matcher): (
        Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>,
        Option<Arc<quartermaster::domain::identity::path_pattern::PathPatternMatcher>>,
    ) = if let Some(ref identity_config) = config.identity {
        if let Some(ref spire_source) = identity_config.spire {
            if !spire_source.path_patterns.is_empty() {
                // Path patterns configured: compile patterns and skip SPIRE API calls
                let matcher = quartermaster::domain::identity::path_pattern::PathPatternMatcher::compile(
                    &spire_source.trust_domain,
                    &spire_source.path_patterns,
                )
                .unwrap_or_else(|errors| {
                    let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                    panic!("invalid path patterns in [identity.spire]: {}", msgs.join("; "));
                });

                // Log warnings for patterns with no named captures
                for warning in matcher.warnings() {
                    tracing::warn!("{}", warning);
                }

                // Log info if server_addr is also configured (it will be ignored)
                if spire_source.server_addr.is_some() {
                    tracing::info!(
                        "server_addr is ignored when path_patterns are configured"
                    );
                }

                tracing::info!(
                    pattern_count = spire_source.path_patterns.len(),
                    "SPIRE identity source using path pattern mode (no API calls)"
                );

                (Arc::new(NoOpSelectorEnricher) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, Some(Arc::new(matcher)))
            } else if let Some(ref addr) = spire_source.server_addr {
                // No path patterns + server_addr present: legacy SPIRE API enrichment
                let spire_api_client: Arc<dyn quartermaster::spireapi::SpireApiClient> =
                    Arc::new(HttpSpireApiClient::new(addr.clone()));
                tracing::info!(
                    server_addr = %addr,
                    "SPIRE identity source using API enrichment mode"
                );
                (Arc::new(SpireSelectorEnricher::new(spire_api_client)) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, None)
            } else {
                // No path patterns + no server_addr: no-op enricher
                tracing::info!("SPIRE identity source using no-op enricher (no server_addr, no path_patterns)");
                (Arc::new(NoOpSelectorEnricher) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, None)
            }
        } else {
            // Identity config exists but no SPIRE source configured
            (Arc::new(NoOpSelectorEnricher) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, None)
        }
    } else if config.spire.is_some() {
        // Legacy SPIRE config present (no server_addr field), use default address
        let spire_api_client: Arc<dyn quartermaster::spireapi::SpireApiClient> =
            Arc::new(HttpSpireApiClient::new("http://localhost:8081".to_string()));
        (Arc::new(SpireSelectorEnricher::new(spire_api_client)) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, None)
    } else {
        // No SPIRE configured anywhere, use no-op enricher
        (Arc::new(NoOpSelectorEnricher) as Arc<dyn quartermaster::domain::billet::selector::SelectorEnricher>, None)
    };

    // Initialize EntityBuilder
    let entity_builder = EntityBuilder::new();

    // Initialize BilletResolverImpl
    let resolver: Arc<dyn quartermaster::domain::billet::Resolver> = if let Some(ref matcher) = path_pattern_matcher {
        // Path-pattern mode: resolver bypasses selector enrichment and uses regex captures
        Arc::new(BilletResolverImpl::with_path_pattern_matcher(
            selector_enricher,
            entity_builder,
            Arc::clone(&local_authorizer),
            Arc::clone(&cache),
            Arc::clone(&policy_sync),
            Duration::from_secs(config.cache.ttl_secs),
            Arc::clone(matcher),
        ))
    } else {
        // Legacy mode: selector enrichment + EntityBuilder
        Arc::new(BilletResolverImpl::new(
            selector_enricher,
            entity_builder,
            Arc::clone(&local_authorizer),
            Arc::clone(&cache),
            Arc::clone(&policy_sync),
            Duration::from_secs(config.cache.ttl_secs),
        ))
    };

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
    // Initialization flow:
    // 1. Parse IdentityConfig from the app config
    // 2. If SPIRE configured: create SPIRE validator for dispatcher
    // 3. If OIDC sources configured: create JwksManager, create DefaultOidcValidator
    // 4. If AWS STS enabled: create DefaultAwsStsValidator
    // 5. If GCP enabled: ensure JwksManager includes Google JWKS source, create DefaultGcpValidator
    // 6. Create DefaultIdentityDispatcher with all configured validators
    // 7. Create MultiSourceEntityBuilder
    // 8. Create ImplicitBilletMapper from OIDC sources

    // Initialize IdentityDispatcher with the SPIRE validator.
    // Priority: config.identity.spire (new) → config.spire (legacy) → None
    let spire_validator_for_dispatcher: Option<Box<dyn quartermaster::domain::svid::Validator>> =
        if let Some(ref identity_config) = config.identity {
            if let Some(ref spire_source) = identity_config.spire {
                // New identity config: use jwks_path for trust bundle and audience field
                let trust_bundle_json = std::fs::read_to_string(&spire_source.jwks_path)
                    .expect("failed to read SPIRE trust bundle from identity.spire.jwks_path");
                let keys = SpireValidator::parse_jwks(&trust_bundle_json)
                    .expect("failed to parse SPIRE trust bundle JWKS from identity.spire.jwks_path");
                Some(Box::new(SpireValidator::new(
                    keys,
                    spire_source.trust_domain.clone(),
                    spire_source.audience.clone(),
                )))
            } else {
                // Identity config exists but no SPIRE source configured
                None
            }
        } else if let Some(ref spire_config) = config.spire {
            // Legacy fallback: use trust_bundle_path and config.issuer as audience
            let trust_bundle_json = std::fs::read_to_string(&spire_config.trust_bundle_path)
                .expect("failed to read SPIRE trust bundle for dispatcher");
            let keys = SpireValidator::parse_jwks(&trust_bundle_json)
                .expect("failed to parse SPIRE trust bundle JWKS for dispatcher");
            Some(Box::new(SpireValidator::new(
                keys,
                spire_config.trust_domain.clone(),
                config.issuer.clone(),
            )))
        } else {
            None
        };

    // ─── Build JwksManager for JWT-based identity sources (OIDC, GCP) ──────────
    // Must be created BEFORE the dispatcher so we can use it as a provider for
    // DefaultOidcValidator (and later DefaultGcpValidator).
    let http_client = reqwest::Client::new();
    let jwks_manager: Option<Arc<JwksManager>> = if let Some(ref identity_config) = config.identity
    {
        if !identity_config.oidc.is_empty()
            || identity_config.gcp.as_ref().is_some_and(|g| g.enabled)
        {
            let manager = Arc::new(JwksManager::from_config(identity_config, http_client.clone()));
            manager.start_refresh_tasks();
            Some(manager)
        } else {
            None
        }
    } else {
        None
    };

    // ─── Build OIDC Validator ──────────────────────────────────────────────────
    let oidc_validator: Option<Box<dyn quartermaster::domain::identity::oidc::OidcValidator>> =
        if let Some(ref identity_config) = config.identity {
            if !identity_config.oidc.is_empty() {
                if let Some(ref manager) = jwks_manager {
                    Some(Box::new(DefaultOidcValidator::new(
                        identity_config.oidc.clone(),
                        Arc::clone(manager),
                    )))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    // ─── Build AWS STS Validator ──────────────────────────────────────────────
    let aws_sts_validator: Option<Box<dyn quartermaster::domain::identity::aws_sts::AwsStsValidator>> =
        if let Some(ref identity_config) = config.identity {
            if let Some(ref aws_sts_config) = identity_config.aws_sts {
                if aws_sts_config.enabled {
                    Some(Box::new(DefaultAwsStsValidator::new(
                        aws_sts_config.clone(),
                        http_client.clone(),
                    )))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    // ─── Build GCP Validator ───────────────────────────────────────────────────
    let gcp_validator: Option<Box<dyn quartermaster::domain::identity::gcp::GcpValidator>> =
        if let Some(ref identity_config) = config.identity {
            if let Some(ref gcp_config) = identity_config.gcp {
                if gcp_config.enabled {
                    if let Some(ref manager) = jwks_manager {
                        Some(Box::new(DefaultGcpValidator::new(
                            gcp_config.clone(),
                            Arc::clone(manager),
                        )))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    let identity_dispatcher: Arc<dyn quartermaster::domain::identity::dispatcher::IdentityDispatcher> =
        Arc::new(DefaultIdentityDispatcher::new(
            spire_validator_for_dispatcher,
            oidc_validator, // OIDC validator — configured via IdentityConfig
            aws_sts_validator, // AWS STS validator — configured via IdentityConfig
            gcp_validator, // GCP validator — configured via IdentityConfig
        ));

    // Initialize MultiSourceEntityBuilder
    let multi_source_entity_builder = Arc::new(MultiSourceEntityBuilder::new(EntityBuilder::new()));

    // Initialize ImplicitBilletMapper from OIDC sources (if configured)
    let implicit_billet_mapper = if let Some(ref identity_config) = config.identity {
        if !identity_config.oidc.is_empty() {
            Arc::new(ImplicitBilletMapper::from_config(&identity_config.oidc))
        } else {
            Arc::new(ImplicitBilletMapper::from_config(&[]))
        }
    } else {
        Arc::new(ImplicitBilletMapper::from_config(&[]))
    };

    // ─── Build MtlsValidator ──────────────────────────────────────────────────
    // Constructed only when BOTH [server.tls] is configured AND
    // [identity.spire].x509_bundle_path is present. Panics on startup if the
    // configured x509_bundle_path file is missing or contains malformed PEM.
    let mtls_validator: Option<Arc<quartermaster::domain::identity::mtls::MtlsValidator>> =
        if config.server.tls.is_some() {
            if let Some(ref identity_config) = config.identity {
                if let Some(ref spire_source) = identity_config.spire {
                    if let Some(ref x509_bundle_path) = spire_source.x509_bundle_path {
                        let ca_pem = std::fs::read(x509_bundle_path).unwrap_or_else(|e| {
                            panic!(
                                "failed to read x509_bundle_path '{}': {}",
                                x509_bundle_path, e
                            )
                        });
                        let validator = quartermaster::domain::identity::mtls::MtlsValidator::from_pem(
                            &ca_pem,
                            &spire_source.trust_domain,
                        )
                        .unwrap_or_else(|e| {
                            panic!(
                                "failed to parse x509_bundle_path '{}': {}",
                                x509_bundle_path, e
                            )
                        });
                        tracing::info!(
                            path = %x509_bundle_path,
                            trust_domain = %spire_source.trust_domain,
                            "mTLS validator initialized from x509_bundle_path"
                        );
                        Some(Arc::new(validator))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    // Build AppState
    let app_state = Arc::new(AppState {
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
        mtls_validator,
        path_pattern_matcher,
    });

    // ─── Start HTTP Server(s) ─────────────────────────────────────────────────
    // Build TLS config if [server.tls] is configured. Panics on startup if
    // cert/key files are missing or malformed (fail-fast for misconfiguration).
    let tls_server_config = config.server.tls.as_ref().map(|tls_config| {
        let rustls_config = server::tls::build_tls_config(tls_config)
            .unwrap_or_else(|e| panic!("failed to build TLS config: {}", e));
        tracing::info!(
            cert_path = %tls_config.cert_path,
            key_path = %tls_config.key_path,
            "TLS configuration loaded"
        );
        Arc::new(rustls_config)
    });

    if let Some(ref admin_addr) = config.server.admin_addr {
        // Split mode: separate admin listener
        let main_router = server::build_main_router(Arc::clone(&app_state), false);
        let admin_router = server::build_admin_router(app_state);

        let main_addr = format!("{}:{}", config.server.host, config.server.port);
        tracing::info!(main_addr = %main_addr, admin_addr = %admin_addr, "starting HTTP servers (split admin)");

        let main_listener = tokio::net::TcpListener::bind(&main_addr)
            .await
            .expect("failed to bind main listener");
        let admin_listener = tokio::net::TcpListener::bind(admin_addr.as_str())
            .await
            .expect("failed to bind admin listener");

        if let Some(tls_config) = tls_server_config {
            // TLS mode: main listener uses TLS with peer cert extraction
            tracing::info!("main listener using TLS");
            tokio::select! {
                _ = server::tls::serve_tls(main_listener, tls_config, main_router) => {}
                result = axum::serve(admin_listener, admin_router) => {
                    result.expect("admin server error");
                }
            }
        } else {
            // Plain HTTP mode (existing behavior)
            tokio::select! {
                result = axum::serve(main_listener, main_router) => {
                    result.expect("main server error");
                }
                result = axum::serve(admin_listener, admin_router) => {
                    result.expect("admin server error");
                }
            }
        }
    } else {
        // Combined mode: all routes on main listener
        let router = server::build_main_router(app_state, true);
        let addr = format!("{}:{}", config.server.host, config.server.port);

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind");

        if let Some(tls_config) = tls_server_config {
            // TLS mode with peer cert extraction
            tracing::info!(addr = %addr, "starting HTTPS server");
            server::tls::serve_tls(listener, tls_config, router).await;
        } else {
            // Plain HTTP mode (existing behavior)
            tracing::info!(addr = %addr, "starting HTTP server");
            axum::serve(listener, router).await.expect("server error");
        }
    }

    // Clean up background tasks (unreachable in practice since serve blocks)
    audit_service.shutdown(Duration::from_secs(5)).await;
    policy_sync_handle.abort();
}
