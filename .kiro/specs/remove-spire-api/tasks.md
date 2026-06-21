# Implementation Plan: Remove SPIRE Server API Dependency

## Overview

This plan covers the complete removal of the SPIRE Server API integration from Quartermaster. Tasks are ordered so the codebase compiles after each major step. The approach is: delete leaf modules first, then refactor dependents, then clean up wiring, tests, and documentation.

## Tasks

- [x] 1. Delete the `spireapi` module and selector files
  - [x] 1.1 Delete `src/spireapi/mod.rs` and remove `pub mod spireapi;` from `src/lib.rs`
    - Delete the entire `src/spireapi/mod.rs` file
    - Remove `pub mod spireapi;` declaration from `src/lib.rs`
    - Remove any `use crate::spireapi::*` imports found elsewhere in the codebase
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 1.2 Delete `src/domain/billet/selector.rs` and remove `pub mod selector;` from `src/domain/billet/mod.rs`
    - Delete the entire `src/domain/billet/selector.rs` file
    - Remove `pub mod selector;` declaration from `src/domain/billet/mod.rs`
    - Remove any `use super::selector::*` or equivalent imports in the billet module
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 1.3 Delete `src/domain/identity/selector_enricher.rs` and remove its module declaration
    - Delete `src/domain/identity/selector_enricher.rs`
    - Remove `pub mod selector_enricher;` from `src/domain/identity/mod.rs`
    - Remove any imports of `SelectorEnricher` or `NoOpSelectorEnricher` from identity module consumers
    - _Requirements: 2.5_

- [x] 2. Refactor `BilletResolverImpl` to remove the legacy code path
  - [x] 2.1 Remove `selector_enricher` and `entity_builder` fields from `BilletResolverImpl`
    - Remove `selector_enricher: Arc<dyn SelectorEnricher>` field from the struct
    - Remove `entity_builder: EntityBuilder` field from the struct
    - Make `path_pattern_matcher` non-Optional: change from `Option<Arc<PathPatternMatcher>>` to `Arc<PathPatternMatcher>`
    - Update the constructor (`new`) to accept the simplified parameter list
    - _Requirements: 3.1, 3.4, 2.5_

  - [x] 2.2 Remove `selectors` field from `ResolverInput`
    - Delete the `selectors: Vec<String>` field from `ResolverInput`
    - Update all construction sites of `ResolverInput` to stop passing `selectors`
    - _Requirements: 3.2_

  - [x] 2.3 Remove the legacy branch in `BilletResolverImpl::resolve()`
    - Delete the `None` arm of the `path_pattern_matcher` match (the selector-enricher code path)
    - Simplify the resolve method to always use path-pattern extraction → `EntityBatchAuthzRequest`
    - Remove any fallback logic that caught `SelectorError`
    - _Requirements: 3.1, 3.3_

- [x] 3. Remove dead code from `src/cedar/mod.rs`
  - [x] 3.1 Remove `BatchAuthzRequest`, `batch_is_authorized`, `WorkloadEntity`, `PlatformType`, and `build_workload_entities`
    - Delete the `BatchAuthzRequest` struct
    - Delete the `batch_is_authorized` method (or its associated impl block)
    - Delete the `WorkloadEntity` struct
    - Delete the `PlatformType` enum
    - Delete the `build_workload_entities` function
    - Remove any tests exercising these removed items
    - _Requirements: 3.1_

- [x] 4. Remove `server_addr` from configuration
  - [x] 4.1 Remove `server_addr` from `SpireSourceConfig` in `src/config/identity.rs`
    - Delete the `server_addr: Option<String>` field from `SpireSourceConfig`
    - _Requirements: 4.1_

  - [x] 4.2 Remove `server_addr` from legacy `SpireConfig` in `src/config/mod.rs` if present
    - Check for and remove `server_addr` field in any legacy SPIRE config struct
    - Remove `QM_SPIRE_SERVER_ADDR` environment variable handling if present
    - _Requirements: 4.2, 4.3_

- [x] 5. Simplify `src/main.rs` wiring
  - [x] 5.1 Remove all SPIRE API client and selector enricher construction
    - Remove `HttpSpireApiClient` import and instantiation
    - Remove `SpireSelectorEnricher` / `NoOpSelectorEnricher` imports and instantiation
    - Remove `EntityBuilder` usage in resolver construction
    - Remove the mode-selection logic that branches on `server_addr`
    - Remove the hardcoded `http://localhost:8081` default
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 4.4_

  - [x] 5.2 Update `BilletResolverImpl` construction in `main.rs`
    - Call the new simplified constructor (authorizer, cache, policy_sync, cache_ttl, path_pattern_matcher)
    - Handle the case where no path_patterns are configured (construct a no-op matcher)
    - _Requirements: 5.4_

- [x] 6. Checkpoint — Ensure `cargo build` passes
  - Run `cargo build` and verify no compilation errors remain
  - Ensure all removed imports, fields, and functions are fully cleaned up
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Update tests
  - [x] 7.1 Remove tests that exercise deleted code
    - Remove all tests in `src/domain/billet/mod.rs` that use `MockSelectorEnricher` or the legacy constructor
    - Remove `BatchAuthzRequest` and `batch_is_authorized` tests from `src/cedar/mod.rs`
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 7.2 Update remaining billet resolver tests to use the new constructor
    - Update test helper functions to use the simplified `BilletResolverImpl::new(...)` signature
    - Ensure tests no longer pass `selector_enricher` or `entity_builder`
    - Ensure tests no longer populate `selectors` on `ResolverInput`
    - _Requirements: 8.2, 8.4_

- [x] 8. Update documentation and config examples
  - [x] 8.1 Update `docs/configuration.md`
    - Remove `server_addr` from all config examples
    - Remove any mention of "selector enrichment" or "SPIRE Server API"
    - _Requirements: 6.1, 6.3_

  - [x] 8.2 Update `example/config.toml`
    - Remove `server_addr` line or comment from the SPIRE config section
    - _Requirements: 6.2_

  - [x] 8.3 Update `README.md` if it references SPIRE Server API calls
    - Remove mentions of SPIRE Server API from the architecture description
    - _Requirements: 6.4_

- [x] 9. Audit `Cargo.toml` for unused dependencies
  - [x] 9.1 Check whether any dependencies are now unused after removal
    - Verify `reqwest` is still used by other modules (OIDC JWKS, AWS STS)
    - Verify `async-trait` and `mockall` are still used by other code
    - Remove any dependency that has no remaining consumers
    - Remove any feature flags only needed by the SPIRE API client
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 10. Final verification
  - Run `cargo build` to confirm the project compiles cleanly
  - Run `cargo test` to confirm all remaining tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- No property-based tests are needed: this is a subtraction-only spec with no new logic
- The `EntityBuilder` in `src/domain/billet/entity_builder.rs` is retained (used by `MultiSourceEntityBuilder`)
- All path-pattern-mode tests are retained unmodified — they validate the surviving code path
- Tasks are ordered to maintain compilability after each major step
