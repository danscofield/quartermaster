# Requirements Document — Remove SPIRE Server API Dependency

## Introduction

This spec removes all SPIRE Server API integration from Quartermaster. The `spireapi/` module, `SelectorEnricher`, `SpireSelectorEnricher`, `HttpSpireApiClient`, and all related config (`server_addr`), wiring, and documentation are deleted. The SPIFFE ID path pattern extraction (see `spiffe-path-patterns` spec) fully replaces selector enrichment.

## Motivation

- The SPIRE Server API adds two network calls to the hot path for data that isn't reliably useful
- Registration entry selectors reflect operator config, not runtime pod state
- The SPIFFE ID itself is attested and carries all identity information when paths are structured correctly
- Regex path patterns provide a superior, zero-network-call approach to attribute extraction
- Removing dead code reduces maintenance burden, attack surface, and confusion

## Requirements

### Requirement 1: Delete `spireapi/` Module

#### Acceptance Criteria

1. Remove `src/spireapi/mod.rs` entirely (contains `HttpSpireApiClient`, `SpireApiClient` trait, `RegistrationEntry`, `SpireApiError`)
2. Remove `pub mod spireapi;` from `src/lib.rs`
3. Remove all `use crate::spireapi::*` imports throughout the codebase

### Requirement 2: Delete `SelectorEnricher` Trait and Implementations

#### Acceptance Criteria

1. Remove `SelectorEnricher` trait from `src/domain/billet/selector.rs`
2. Remove `SpireSelectorEnricher` struct and implementation
3. Remove `NoOpSelectorEnricher` struct and implementation
4. Remove the entire `src/domain/billet/selector.rs` file if nothing else remains
5. Remove all references to `SelectorEnricher` from `BilletResolverImpl`, `main.rs`, and tests

### Requirement 3: Remove Selector Enrichment from Billet Resolution

#### Acceptance Criteria

1. THE `BilletResolverImpl` SHALL NOT call any selector enrichment step
2. THE `ResolverInput` (or equivalent) SHALL NOT contain a `selectors` field sourced from SPIRE API
3. Cedar `context.selectors` SHALL be populated from SPIFFE ID path pattern captures (see `spiffe-path-patterns` spec) or be an empty set — never from a SPIRE API call
4. Remove `selector_enricher` from `BilletResolverImpl` constructor and struct

### Requirement 4: Remove SPIRE API Config

#### Acceptance Criteria

1. Remove `server_addr` from `SpireSourceConfig` (in `src/config/identity.rs`)
2. Remove `server_addr` from legacy `SpireConfig` (in `src/config/mod.rs`) if it exists
3. Remove any `QM_SPIRE_SERVER_ADDR` environment variable handling
4. Remove the hardcoded `http://localhost:8081` default from `main.rs`

### Requirement 5: Update `main.rs` Wiring

#### Acceptance Criteria

1. Remove construction of `HttpSpireApiClient`
2. Remove construction of `SpireSelectorEnricher` or `NoOpSelectorEnricher`
3. Remove passing `selector_enricher` to `BilletResolverImpl`
4. THE billet resolver SHALL be constructed without any enricher dependency

### Requirement 6: Update Configuration Documentation

#### Acceptance Criteria

1. Remove `server_addr` from all config examples in `docs/configuration.md`
2. Remove `server_addr` from `example/config.toml`
3. Remove any mention of "selector enrichment" or "SPIRE Server API" from documentation
4. Update README.md to remove references to SPIRE Server API calls in the architecture description

### Requirement 7: Update Design Documents

#### Acceptance Criteria

1. Remove references to `SPIRE_API` from architecture diagrams in spec design docs
2. Remove `SelectorEnricher` from component lists
3. Remove "fetch selectors" steps from sequence diagrams
4. The `spiffe-path-patterns` spec becomes the sole mechanism for extracting workload attributes from SPIRE-sourced identities

### Requirement 8: Clean Up Tests

#### Acceptance Criteria

1. Remove all tests in `src/domain/billet/selector.rs`
2. Remove all `MockSelectorEnricher` usages in billet resolver tests — replace with direct attribute passing from path pattern extraction
3. Remove `SpireApiClient` mock expectations from any integration tests
4. Ensure all remaining tests pass after removal

### Requirement 9: Clean Up Cargo.toml

#### Acceptance Criteria

1. Audit all dependencies in `Cargo.toml` — remove any that are no longer used after the SPIRE API removal
2. IF `reqwest` is only used by `HttpSpireApiClient` and no other module, remove it (check: likely still used by OIDC JWKS fetching and AWS STS validation)
3. Remove any feature flags that were only needed for the SPIRE API client
4. Run `cargo udeps` or `cargo machete` (if available) to identify other unused dependencies introduced during development
5. Ensure `cargo build` and `cargo test` pass after dependency removal
