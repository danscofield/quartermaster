# Requirements Document — Server Wiring Gaps

## Introduction

Multiple implemented features are not connected in `main.rs`. This spec covers wiring all remaining gaps: multi-source identity (OIDC, AWS STS, GCP), Redis cache, KMS-delegated CA, configurable SPIRE API address, policy sync interval from `[datastore]`, and the optional separate admin listener.

## Requirements

### Requirement 1: Add `identity` to Config and Wire All Identity Sources

#### Acceptance Criteria

1. THE `Config` struct SHALL have a `pub identity: Option<IdentityConfig>` field, deserialized from the `[identity]` TOML section
2. IF `config.identity` contains OIDC entries, THE server SHALL construct `JwksManager`, `DefaultOidcValidator`, and pass it to the dispatcher as `Some(...)`
3. IF `config.identity` contains `aws_sts` with `enabled = true`, THE server SHALL construct the AWS STS validator and pass it to the dispatcher
4. IF `config.identity` contains `gcp` with `enabled = true`, THE server SHALL construct the GCP validator, add Google's JWKS to the JwksManager, and pass it to the dispatcher
5. IF `config.identity` contains OIDC sources with `implicit_claims`, THE server SHALL construct `ImplicitBilletMapper` from those configs
6. THE SPIRE validator for the dispatcher SHALL be constructed from `config.identity.spire` if present, falling back to legacy `config.spire`, or `None` if neither exists
7. THE standalone `validator` field in AppState SHALL be removed or unified with the dispatcher — one SPIRE initialization path, not two

### Requirement 2: Configurable SPIRE API Address

#### Acceptance Criteria

1. IF `config.identity.spire.server_addr` is present, THE `HttpSpireApiClient` SHALL use that address
2. IF only legacy `config.spire` is present (no `server_addr`), use default `http://localhost:8081`
3. IF SPIRE is not configured anywhere, selector enrichment SHALL use a no-op enricher returning empty selectors

### Requirement 3: Redis Cache Wiring

#### Acceptance Criteria

1. IF `config.cache.backend == "redis"`, THE server SHALL construct a Redis-backed cache using the URL from `config.redis`
2. IF `config.cache.backend == "redis"` but `config.redis` is `None`, startup SHALL fail with a descriptive error
3. IF `config.cache.backend == "memory"` (default), behavior is unchanged

### Requirement 4: KMS-Delegated CA Wiring

#### Acceptance Criteria

1. IF `config.ca_backend` is present, THE server SHALL use the KeyManager factory to build the CA key manager (same factory as signing, with purpose = "ca")
2. THE `LocalAuthority` SHALL accept a `KeyManager` for signing instead of raw PEM bytes (or a new CA impl that delegates to KeyManager)
3. IF `config.ca_backend` is absent, fall back to legacy `config.ca` (load PEM files directly, current behavior)

### Requirement 5: Policy Sync Interval from DataStore Config

#### Acceptance Criteria

1. THE `DataStoreConfig` struct SHALL include a `policy_sync_interval_secs: u64` field (default: 30)
2. THE `PolicySyncService` SHALL use `config.datastore.policy_sync_interval_secs` when `[datastore]` is present
3. Fall back to `config.dynamo.policy_sync_interval_secs` if only legacy config exists, then to default 30s

### Requirement 6: Separate Admin Listener

#### Acceptance Criteria

1. IF `config.server.admin_addr` is present (e.g., `"0.0.0.0:8444"`), THE server SHALL bind a second listener serving only admin routes (`/admin/*`)
2. THE main listener SHALL NOT serve admin routes when a separate admin listener is configured
3. IF `config.server.admin_addr` is absent, all routes (including admin) are served on the main listener (current behavior)

### Requirement 7: Startup Validation

#### Acceptance Criteria

1. IF `[identity]` is configured, at least one identity source must be enabled — startup fails otherwise
2. IF neither `[identity]` nor legacy `[spire]` is configured, THE server SHALL start but token exchange returns 401 for all source types (admin API still functions)
3. IF `[signing_backend]` is `kms_delegated` but no KMS sub-config (aws_kms or gcp_kms) is provided, startup SHALL fail
4. IF `[ca_backend]` is `kms_delegated` but no KMS sub-config is provided, startup SHALL fail
