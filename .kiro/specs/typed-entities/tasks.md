# Implementation Plan: Wire Typed Cedar Entities into Billet Resolution

## Overview

This plan wires existing typed Cedar entity construction code into the live billet resolution path, renames `HumanIdentity` → `OidcIdentity`, fixes OIDC claims flattening, adds `TypedPrincipal` to `ResolverInput`, removes dead SPIRE entity code, and updates the Cedar schema. Tasks are ordered so each builds on the previous, with property tests placed close to the code they validate.

## Tasks

- [ ] 1. Rename `HumanIdentity` → `OidcIdentity` and extend `OidcEntity`
  - [x] 1.1 Rename `HumanEntity` struct to `OidcEntity` and add new fields in `src/domain/identity/entity.rs`
    - Rename `HumanEntity` → `OidcEntity`
    - Add `subject: String`, `subject_type: String`, and `claims: Vec<String>` fields to the struct
    - Rename `CedarPrincipal::Human(HumanEntity)` → `CedarPrincipal::Oidc(OidcEntity)`
    - Rename `build_human_entity()` → `build_oidc_entity()` and update it to populate `subject`, `subject_type` (default `"human"`), and `claims` (formatted as `"claim_name:value"`)
    - Update all match arms in `build_cedar_entity()`, `principal_entity_uid()`, and `build_principal()` to use the new variant name
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2_

  - [x] 1.2 Rename `build_human_cedar_entity()` → `build_oidc_cedar_entity()` and update Cedar entity type
    - Change the Cedar entity type string from `"HumanIdentity"` to `"OidcIdentity"` in `make_entity_uid` calls
    - Add `subject`, `subject_type`, and `claims` as Cedar entity attributes (String and Set<String> respectively)
    - Update `principal_entity_uid()` for the `Oidc` variant to use `"OidcIdentity"`
    - _Requirements: 2.1, 2.2, 3.2, 5.3_

  - [ ]* 1.3 Write property test for entity type routing correctness
    - **Property 1: Entity type routing correctness**
    - Generate random `AuthenticatedIdentity` variants (Oidc, AwsSts, Gcp) via `proptest`
    - Verify `principal_entity_uid()` returns entity UID with correct type name for each variant: Oidc → `"OidcIdentity"`, AwsSts → `"AwsRoleIdentity"`, Gcp → `"GcpIdentity"`
    - **Validates: Requirements 1.1, 2.1**

  - [ ]* 1.4 Write property test for OIDC entity claims transformation
    - **Property 2: OIDC entity claims transformation**
    - Generate random `OidcIdentity` with arbitrary claims maps via `proptest`
    - Verify `groups` equals sorted, deduplicated union of all claim values
    - Verify `claims` equals sorted, deduplicated set of `"claim_name:value"` strings
    - Verify `subject_type` is `"human"`, and `email`/`idp_prefix`/`subject` match input
    - **Validates: Requirements 2.4, 3.1, 3.2**

  - [ ]* 1.5 Write property test for claims set completeness (no data loss)
    - **Property 3: Claims set completeness**
    - Generate random claims maps via `proptest`
    - For every (claim_name, value) pair in input, verify `claims` contains `"claim_name:value"` and `groups` contains `value`
    - **Validates: Requirements 3.1, 3.2**

- [x] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Add `TypedPrincipal` to `ResolverInput` and update resolver
  - [x] 3.1 Define `TypedPrincipal` struct and add it to `ResolverInput` in `src/domain/billet/mod.rs`
    - Add `TypedPrincipal` struct with fields: `principal_type: String`, `principal_id: String`, `entities: Vec<Entity>`, `source_type: String`, `source_cloud: String`
    - Add `typed_principal: Option<TypedPrincipal>` field to `ResolverInput`
    - _Requirements: 1.1, 1.2_

  - [x] 3.2 Update `BilletResolverImpl.resolve()` to branch on `typed_principal`
    - When `typed_principal` is `Some`, skip path-pattern extraction and use provided entities/metadata directly for Cedar authorization
    - When `typed_principal` is `None`, use existing SPIRE path (path_pattern_matcher → build_workload_entities_from_captures)
    - Build `CommonContext` with the correct `source_type` and `source_cloud` from `TypedPrincipal`
    - _Requirements: 1.1, 1.2, 1.3_

  - [ ]* 3.3 Write property test for entity construction producing valid Cedar entities
    - **Property 4: Entity construction produces valid Cedar entities**
    - Generate random non-SPIRE `AuthenticatedIdentity` variants via `proptest`
    - Verify `build_cedar_entity()` returns `Ok` and entity UID matches `principal_entity_uid()` for the same principal
    - **Validates: Requirements 1.2**

- [ ] 4. Wire handler to build typed entities for non-SPIRE sources
  - [x] 4.1 Update `build_resolver_input()` in `src/handler/token.rs` to build `TypedPrincipal` for non-SPIRE sources
    - For `AuthenticatedIdentity::Oidc`, `AwsSts`, and `Gcp`: call `state.entity_builder.build_principal()`, then `build_cedar_entity()` and `principal_entity_uid()` to construct `TypedPrincipal`
    - Set `typed_principal: Some(...)` on the `ResolverInput` for these variants
    - For `AuthenticatedIdentity::Spire`: keep `typed_principal: None` and existing SPIRE fields
    - Map `EntityBuildError` to `DomainError::service_unavailable` (500)
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 4.2 Remove `selectors` parameter from `MultiSourceEntityBuilder::build_principal()`
    - Remove the `selectors: &[String]` parameter since SPIRE no longer goes through this path
    - Update all call sites
    - _Requirements: 4.6_

  - [ ]* 4.3 Write unit tests for handler typed-entity wiring
    - Test that OIDC identity produces `TypedPrincipal` with `principal_type = "OidcIdentity"`
    - Test that AWS STS identity produces `TypedPrincipal` with `principal_type = "AwsRoleIdentity"`
    - Test that GCP identity produces `TypedPrincipal` with `principal_type = "GcpIdentity"`
    - Test that SPIRE identity produces `typed_principal = None`
    - _Requirements: 1.1, 1.2_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Remove dead SPIRE entity code
  - [x] 6.1 Remove `PlatformType` enum and `WorkloadEntity` struct from `src/cedar/mod.rs`
    - Delete `PlatformType` enum definition
    - Delete `WorkloadEntity` struct definition
    - Update any remaining imports that reference these types
    - _Requirements: 4.1, 4.2_

  - [x] 6.2 Delete `src/domain/billet/entity_builder.rs` entirely
    - Remove the file
    - Remove `pub mod entity_builder;` from `src/domain/billet/mod.rs`
    - _Requirements: 4.3_

  - [x] 6.3 Remove `CedarPrincipal::Workload` variant and SPIRE arm from `build_principal`
    - Remove `CedarPrincipal::Workload(WorkloadEntity)` variant from enum
    - Remove the `AuthenticatedIdentity::Spire` match arm in `build_principal()` (SPIRE no longer routed through `MultiSourceEntityBuilder`)
    - Remove corresponding match arm in `build_cedar_entity()` and `principal_entity_uid()`
    - Remove `use crate::cedar::WorkloadEntity` and `use crate::domain::billet::entity_builder::*` imports
    - _Requirements: 4.4, 4.5_

  - [x] 6.4 Remove `spire_builder` field from `MultiSourceEntityBuilder`
    - Remove the `spire_builder: EntityBuilder` field
    - Update `MultiSourceEntityBuilder::new()` to take no parameters
    - Update all call sites that construct `MultiSourceEntityBuilder` (AppState initialization in bootstrap)
    - _Requirements: 4.5, 4.7_

  - [ ]* 6.5 Write compile-verification unit test for dead code removal
    - Add a test that asserts `MultiSourceEntityBuilder::new()` takes no arguments
    - Add a test that `build_principal()` takes only `&AuthenticatedIdentity` (no selectors)
    - Verify no references to `PlatformType`, `WorkloadEntity`, or `entity_builder` remain
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [ ] 7. Update Cedar schema
  - [x] 7.1 Update Cedar schema to declare all principal types and their attributes
    - Add `OidcIdentity` entity type with attributes: `email: String`, `idp_prefix: String`, `subject: String`, `subject_type: String`, `groups: Set<String>`, `claims: Set<String>`
    - Ensure `AwsRoleIdentity` declares: `account_id: String`, `role_arn: String`, `role_name: String`, `role_path: String`
    - Ensure `GcpIdentity` declares: `project_id: String`, `email: String`, `zone: String`
    - Update `assumeBillet` action's `principalTypes` to include: `Workload`, `OidcIdentity`, `AwsRoleIdentity`, `GcpIdentity`
    - Update all admin actions to accept these types as principals
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 7.2 Write schema validation tests
    - Load Cedar schema and verify `assumeBillet` accepts all 4 principal types
    - Verify `OidcIdentity` declares all 6 attributes
    - Verify `AwsRoleIdentity` declares all 4 attributes
    - Verify `GcpIdentity` declares all 3 attributes
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ] 8. Update existing tests to use renamed types
  - [x] 8.1 Update all existing tests in `src/domain/identity/entity.rs` to use `OidcEntity`/`CedarPrincipal::Oidc`
    - Replace `HumanEntity` with `OidcEntity` in test construction
    - Replace `CedarPrincipal::Human` with `CedarPrincipal::Oidc` in assertions
    - Update entity UID assertions from `"HumanIdentity"` to `"OidcIdentity"`
    - Remove any tests referencing `CedarPrincipal::Workload` (dead code path)
    - _Requirements: 2.1, 2.2, 2.3_

- [x] 9. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The SPIRE resolution path (`build_workload_entities_from_captures`) remains completely unchanged
- `AppState.entity_builder` is kept — it's now used by the handler to build typed entities for non-SPIRE sources
