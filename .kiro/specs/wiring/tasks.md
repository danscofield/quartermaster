# Implementation Plan: Server Wiring Gaps

## Overview

Wire all remaining implemented-but-disconnected features into Quartermaster's `main.rs` startup sequence. This involves config changes (adding `identity` field to `Config`, `policy_sync_interval_secs` to `DataStoreConfig`, `admin_addr` to `ServerConfig`), constructing identity validators from config, adding Redis cache support, building a KMS-backed CA, implementing a no-op selector enricher, splitting admin routes to a separate listener, and adding startup validation for identity sources.

## Tasks

- [x] 1. Config struct additions
  - [x] 1.1 Add `identity: Option<IdentityConfig>` field to `Config` in `src/config/mod.rs`
    - Add `pub identity: Option<IdentityConfig>` to the `Config` struct
    - Ensure TOML deserialization picks up the `[identity]` section
    - Update `Config::from_env()` to set `identity: None` (env-only mode does not support full identity config)
    - Update the `valid_config()` helper in tests to include `identity: None`
    - _Requirements: 1.1_

  - [x] 1.2 Add `policy_sync_interval_secs` field to `DataStoreConfig` in `src/config/backends.rs`
    - Add `#[serde(default = "default_policy_sync_interval_secs")] pub policy_sync_interval_secs: u64` to `DataStoreConfig`
    - Add the `default_policy_sync_interval_secs` function returning 30
    - _Requirements: 5.1_

  - [x] 1.3 Add `admin_addr: Option<String>` field to `ServerConfig` in `src/config/mod.rs`
    - Add `pub admin_addr: Option<String>` to `ServerConfig`
    - _Requirements: 6.1_

  - [ ]* 1.4 Write unit tests for config additions
    - Test TOML deserialization with `[identity]` section present/absent
    - Test `DataStoreConfig` with explicit and default `policy_sync_interval_secs`
    - Test `ServerConfig` with and without `admin_addr`
    - _Requirements: 1.1, 5.1, 6.1_

- [x] 2. Startup validation for identity config
  - [x] 2.1 Extend `Config::validate()` to validate `identity` when present
    - If `config.identity` is `Some`, call `identity.validate()` and map `IdentityConfigError` to `ConfigError`
    - If `config.identity` is `None` and `config.spire` is `None`, allow startup (no identity sources — token exchange returns 401)
    - _Requirements: 7.1, 7.2_

  - [ ]* 2.2 Write unit tests for identity startup validation
    - Test that `identity` with no enabled sources fails validation
    - Test that neither `identity` nor `spire` allows startup (no panic)
    - Test that `identity` with at least one source passes validation
    - _Requirements: 7.1, 7.2_

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. NoOp selector enricher and SPIRE address configuration
  - [x] 4.1 Implement `NoOpSelectorEnricher` in `src/domain/billet/selector.rs`
    - Add a `NoOpSelectorEnricher` struct that implements `SelectorEnricher`
    - `fetch_selectors` returns `Ok(vec![])` for any input
    - _Requirements: 2.3_

  - [x] 4.2 Wire configurable SPIRE API address in `main.rs`
    - If `config.identity.spire.server_addr` is present, use that address for `HttpSpireApiClient`
    - If only legacy `config.spire` is present (no `server_addr` field), use default `http://localhost:8081`
    - If SPIRE is not configured anywhere, use `NoOpSelectorEnricher` instead of `SpireSelectorEnricher`
    - _Requirements: 2.1, 2.2, 2.3_

  - [ ]* 4.3 Write unit tests for NoOpSelectorEnricher
    - Test that `fetch_selectors` always returns empty vec
    - _Requirements: 2.3_

- [x] 5. Redis cache wiring
  - [x] 5.1 Create `src/domain/cache/redis.rs` implementing the `Cache` trait
    - Add `redis` crate to `Cargo.toml` dependencies (with `tokio-comp` and `connection-manager` features)
    - Implement `RedisCache` struct with `redis::aio::ConnectionManager`
    - Key format: `qm:cache:{subject}:{audience}`
    - Use Redis `SETEX` for TTL-based expiration
    - Store entries as JSON (`{"billets": [...], "stored_at": "..."}`)
    - Register the module in `src/domain/cache/mod.rs`
    - _Requirements: 3.1_

  - [x] 5.2 Wire Redis cache construction in `main.rs`
    - If `config.cache.backend == CacheBackend::Redis`, construct `RedisCache` using `config.redis.url`
    - If `config.cache.backend == CacheBackend::Redis` but `config.redis` is `None`, startup fails (already handled by `Config::validate()`)
    - If `config.cache.backend == CacheBackend::Memory`, use `InMemoryCache` (current behavior)
    - _Requirements: 3.1, 3.2, 3.3_

  - [ ]* 5.3 Write unit tests for RedisCache
    - Test key formatting
    - Test serialization/deserialization of cache entries
    - Integration test with Redis (skip if unavailable)
    - _Requirements: 3.1_

- [x] 6. KMS-backed CA wiring
  - [x] 6.1 Create `src/domain/cert/kms_authority.rs` implementing the `Authority` trait
    - `KmsBackedAuthority` holds `Arc<dyn KeyManager>`, CA cert PEM, and TTL
    - Reuse CSR verification logic from `LocalAuthority` (extract to helper functions or call `LocalAuthority::verify_csr_signature`)
    - Certificate parameter construction (SPIFFE ID as CN, URI SANs, validity, KU/EKU) follows same logic as `LocalAuthority`
    - Signing step delegates to `KeyManager` instead of a local PEM key
    - Register the module in `src/domain/cert/mod.rs`
    - _Requirements: 4.1, 4.2_

  - [x] 6.2 Wire CA backend selection in `main.rs`
    - If `config.ca_backend` is present, use `keymanager::factory::build_key_manager(ca_backend, data_store, "ca")` to build a CA key manager, then construct `KmsBackedAuthority`
    - If `config.ca_backend` is absent, fall back to legacy `config.ca` (load PEM files directly, current behavior with `LocalAuthority`)
    - Startup validation already ensures `kms_delegated` without KMS sub-config fails
    - _Requirements: 4.1, 4.2, 4.3, 7.3, 7.4_

  - [ ]* 6.3 Write unit tests for KmsBackedAuthority
    - Test certificate issuance with a mock KeyManager
    - Verify subject CN, URI SANs, validity period, KU/EKU match spec
    - _Requirements: 4.1, 4.2_

  - [ ]* 6.4 Write property test for KmsBackedAuthority certificate issuance
    - **Property 6: KMS-backed Authority certificate issuance**
    - Generate random CSRs, SPIFFE IDs, billet sets
    - Verify: CN == SPIFFE ID, URI SANs correct, validity == TTL, KU/EKU correct
    - **Validates: Requirements 4.1, 4.2**

- [x] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Policy sync interval resolution
  - [x] 8.1 Implement `resolve_policy_sync_interval` helper function
    - Add a helper in `main.rs` (or a utility module) that resolves the sync interval with cascading priority: `config.datastore.policy_sync_interval_secs` → `config.dynamo.policy_sync_interval_secs` → 30
    - Wire this into the `PolicySyncService::new()` call, replacing the current hardcoded `config.dynamo.as_ref().map(|d| d.policy_sync_interval_secs).unwrap_or(30)`
    - _Requirements: 5.1, 5.2, 5.3_

  - [ ]* 8.2 Write property test for policy sync interval resolution
    - **Property 3: Policy sync interval cascading resolution**
    - Generate all combinations of datastore present/absent and dynamo present/absent with varying interval values
    - Verify correct cascading: datastore value takes precedence, then dynamo, then default 30
    - **Validates: Requirements 5.1, 5.2, 5.3**

- [x] 9. Multi-source identity wiring
  - [x] 9.1 Wire SPIRE identity source from `config.identity` in `main.rs`
    - If `config.identity.spire` is present, construct `SpireValidator` from it (using `jwks_path` for trust bundle and `audience`)
    - If only legacy `config.spire` is present, construct `SpireValidator` from legacy config (current behavior)
    - If neither exists, SPIRE validator is `None`
    - Pass the constructed validator (or `None`) to the dispatcher
    - _Requirements: 1.6_

  - [x] 9.2 Wire OIDC identity sources from `config.identity` in `main.rs`
    - If `config.identity.oidc` is non-empty, build `JwksManager` with all OIDC sources
    - Construct `DefaultOidcValidator` with the OIDC configs and JwksManager as provider
    - Pass `Some(Box::new(oidc_validator))` to the dispatcher
    - _Requirements: 1.2_

  - [x] 9.3 Wire AWS STS identity source from `config.identity` in `main.rs`
    - If `config.identity.aws_sts` is present and `enabled == true`, construct `DefaultAwsStsValidator` with its config and a shared `reqwest::Client`
    - Pass `Some(Box::new(aws_sts_validator))` to the dispatcher
    - _Requirements: 1.3_

  - [x] 9.4 Wire GCP identity source from `config.identity` in `main.rs`
    - If `config.identity.gcp` is present and `enabled == true`, add Google's JWKS URL to the `JwksManager` (if not already added from OIDC step)
    - Construct `DefaultGcpValidator` with the GCP config and JwksManager as provider
    - Pass `Some(Box::new(gcp_validator))` to the dispatcher
    - _Requirements: 1.4_

  - [x] 9.5 Wire ImplicitBilletMapper from OIDC sources
    - If `config.identity.oidc` contains sources with `implicit_claims`, construct `ImplicitBilletMapper::from_config` with those configs
    - If no OIDC sources or no implicit claims, use empty config (current behavior)
    - _Requirements: 1.5_

  - [x] 9.6 Start JwksManager refresh tasks and assign to AppState
    - If JwksManager was created (OIDC or GCP sources present), call `manager.start_refresh_tasks()`
    - Assign `Some(manager)` to `AppState.jwks_manager`
    - Otherwise assign `None`
    - _Requirements: 1.2, 1.4_

  - [ ]* 9.7 Write property test for dispatcher validator presence
    - **Property 2: Dispatcher validator presence matches enabled identity sources**
    - Generate `IdentityConfig` with varying combinations of enabled/disabled sources
    - Run wiring logic helper, verify dispatcher has `Some(validator)` for exactly enabled sources
    - **Validates: Requirements 1.2, 1.3, 1.4, 1.6**

- [x] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Separate admin listener
  - [x] 11.1 Implement `build_main_router` and `build_admin_router` in `src/server/mod.rs`
    - Add `pub fn build_main_router(state: Arc<AppState>, include_admin: bool) -> Router` that conditionally excludes `/admin/*` routes
    - Add `pub fn build_admin_router(state: Arc<AppState>) -> Router` with only admin routes and middleware
    - Keep existing `build_router` as a backward-compatible wrapper calling `build_main_router(state, true)`
    - _Requirements: 6.1, 6.2, 6.3_

  - [x] 11.2 Wire conditional admin listener in `main.rs`
    - If `config.server.admin_addr` is present, bind a second `TcpListener` on that address serving `build_admin_router`
    - Build the main router with `build_main_router(state, false)` (excludes admin routes from main listener)
    - Use `tokio::select!` or spawn both listeners as concurrent tasks
    - If `config.server.admin_addr` is absent, use `build_main_router(state, true)` (all routes on main listener, current behavior)
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ]* 11.3 Write unit tests for router split
    - Test `build_main_router(include_admin: false)` returns 404 for `/admin/billets`
    - Test `build_main_router(include_admin: true)` serves admin routes
    - Test `build_admin_router` serves `/admin/billets` but returns 404 for `/token`
    - _Requirements: 6.1, 6.2, 6.3_

- [x] 12. Final integration and cleanup
  - [x] 12.1 Remove the standalone `validator` field from `AppState`
    - Remove `pub validator: Option<Arc<dyn Validator>>` from `AppState` in `src/server/mod.rs`
    - Update any handlers that reference `state.validator` to use `state.identity_dispatcher` instead
    - Remove the duplicate SPIRE validator construction in `main.rs` (the one building `validator` separate from the dispatcher)
    - _Requirements: 1.7_

  - [x] 12.2 Update example config to document new sections
    - Add `[identity]` section examples to `example/config.toml`
    - Add `admin_addr` example to `[server]` section
    - Add `policy_sync_interval_secs` to `[datastore]` example
    - _Requirements: 1.1, 5.1, 6.1_

  - [ ]* 12.3 Write property test for identity config deserialization round-trip
    - **Property 1: Identity config deserialization round-trip**
    - Generate arbitrary `IdentityConfig` values, serialize to TOML, deserialize back
    - Verify structural equivalence
    - **Validates: Requirements 1.1**

  - [ ]* 12.4 Write property test for identity validation rejects empty configs
    - **Property 4: Identity config validation rejects configs with no enabled sources**
    - Generate `IdentityConfig` where SPIRE is None, OIDC is empty, AWS STS disabled, GCP disabled
    - Verify `validate()` returns `NoSourcesConfigured` error
    - **Validates: Requirements 7.1**

- [x] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The `redis` crate dependency is needed for task 5.1
- The `validator` field removal (task 12.1) should be done after identity dispatcher wiring is complete to avoid breaking intermediate compilation
