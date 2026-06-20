# Implementation Plan: Uniform Resource Scope Validation

## Overview

Extend `PolicyCrudService` to enforce resource scope validation on all policy actions (not just `assumeBillet`). Add a config-driven system billet exemption list, update the constructor to accept it, remove the action-specific bypass, and update error messages to be action-agnostic. Property-based tests validate the 5 correctness properties using `proptest`.

## Tasks

- [x] 1. Add `system_billets` config field
  - [x] 1.1 Add `system_billets: Vec<String>` field with `#[serde(default = "default_system_billets")]` to `Config` in `src/config/mod.rs`
    - Add the `default_system_billets()` function returning `vec!["quartermaster-admin", "quartermaster-guardrails"]`
    - Add the field after existing optional fields in the `Config` struct
    - Update `Config::from_env()` to populate `system_billets` with the default value
    - _Requirements: 2.3_

  - [x] 1.2 Add unit test for config deserialization with `system_billets`
    - Test that omitting `system_billets` from TOML yields the default list
    - Test that providing a custom list overrides defaults
    - _Requirements: 2.3_

- [x] 2. Refactor `PolicyCrudService` to store system billets
  - [x] 2.1 Add `system_billets: Vec<String>` field to `PolicyCrudService` struct and update constructor
    - Change `PolicyCrudService::new` to accept `system_billets: Vec<String>` as second parameter
    - Store `system_billets` in the struct
    - Add `fn is_system_billet(&self, billet_name: &str) -> bool` instance method
    - _Requirements: 2.1, 2.2, 2.3, 5.3_

  - [x] 2.2 Update `PolicyCrudService::new` call site in `src/main.rs`
    - Pass `config.system_billets.clone()` to the updated constructor
    - _Requirements: 2.3_

  - [x] 2.3 Update existing unit tests in `policies.rs` to use new constructor signature
    - Add a default system billets vec (or empty vec) to all test `PolicyCrudService::new(...)` calls
    - _Requirements: 2.3_

- [x] 3. Remove action-specific bypass and update validation
  - [x] 3.1 Remove `action_is_assume_billet` function entirely from `PolicyCrudService`
    - Delete the `action_is_assume_billet` method
    - Remove the `if !Self::action_is_assume_billet(...) { continue; }` line in `validate_resource_scope`
    - All policies in the set are now validated regardless of action
    - _Requirements: 5.1, 5.4, 1.1_

  - [x] 3.2 Update error messages in `validate_resource_scope` and `check_resource_entity_uid` to be action-agnostic
    - Change `"assumeBillet policies must specify a resource scope..."` → `"policies must specify resource == Billet::<owning billet>; unconstrained resource is not allowed"`
    - Change `"assumeBillet policy resource must be of type Billet, found '{}'"` → `"policy resource must be of type Billet, found '{}'"`
    - Change `"assumeBillet policies must use resource == Billet::\"<name>\" with the owning billet name"` → `"policies must use resource == Billet::<owning billet> with the owning billet name"`
    - _Requirements: 1.2, 1.3_

  - [x] 3.3 Replace hardcoded `quartermaster-guardrails` exemption check with `is_system_billet` in `create` and `update`
    - In `create`: replace `if billet_name != "quartermaster-guardrails"` with `if !self.is_system_billet(billet_name)`
    - In `update`: same replacement
    - Keep the `validate_forbid_only` check for `quartermaster-guardrails` unchanged (separate concern)
    - _Requirements: 2.1, 2.2, 5.3, 1.5_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Property-based tests with proptest
  - [x] 5.1 Write property test: valid resource scope passes for any action
    - **Property 1: Valid resource scope passes for any action**
    - Generate random action strings (assumeBillet, createPolicy, updatePolicy, deletePolicy, readBillet, updateBillet, deleteBillet) and random billet names
    - Build Cedar policy with `resource == Billet::"<name>"` and the generated action
    - Assert `validate_resource_scope` returns `Ok(())`
    - **Validates: Requirements 1.1, 5.2**

  - [x] 5.2 Write property test: invalid resource scope rejected for any action
    - **Property 2: Invalid resource scope rejected for any action**
    - Generate random action × (mismatched billet name OR unconstrained resource)
    - Assert `validate_resource_scope` returns `Err(InvalidResourceScope(_))`
    - **Validates: Requirements 1.2, 1.3**

  - [x] 5.3 Write property test: system billet exemption
    - **Property 3: System billet exemption**
    - Generate random policy content (valid/invalid resource) × billet name from the system billets list
    - Assert that `is_system_billet` returns true and the `create`/`update` path skips validation
    - **Validates: Requirements 2.1, 2.2, 2.3**

  - [x] 5.4 Write property test: principal is unconstrained
    - **Property 4: Principal is unconstrained**
    - Generate random principal entity (any billet, any entity type, unconstrained) with correct resource scope
    - Assert `validate_resource_scope` returns `Ok(())` regardless of principal
    - **Validates: Requirements 4.1, 4.2**

  - [x] 5.5 Write property test: multi-statement rejection
    - **Property 5: Multi-statement rejection**
    - Generate Cedar policy sets with ≥1 valid + ≥1 invalid statement
    - Assert `validate_resource_scope` returns `Err(InvalidResourceScope(_))`
    - **Validates: Requirements 1.4**

- [x] 6. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The design uses Rust throughout — no language selection needed
- `proptest` is the PBT library for Rust; add it as a dev-dependency in `Cargo.toml`
- The `validate_forbid_only` check for `quartermaster-guardrails` is a separate concern and remains unchanged
- Existing policies in the DataStore are not retroactively validated (write-time only enforcement)
- `PolicySyncService` is unaffected — it loads policies without resource scope validation
