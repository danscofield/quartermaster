# Implementation Plan: Billet Tags & Global Guardrail Policies

## Overview

This plan implements billet tags and global guardrail policies for the Quartermaster authorization system. Tasks are organized to build incrementally: data model changes first, then validation logic, then service-layer integration, then entity enrichment at evaluation time, and finally the bootstrap and API wiring.

## Tasks

- [x] 1. Add `tags` field to `BilletMetadata` and DynamoDB persistence
  - [x] 1.1 Add `tags: Vec<String>` field to the `BilletMetadata` struct in `src/dynamo/mod.rs`
    - Add the field to the struct definition
    - Update `get_billet_metadata` to read a `tags` StringSet attribute from DynamoDB (using a new `get_string_set` helper)
    - Update `put_billet_metadata` to write the `tags` field as a DynamoDB StringSet (SS) attribute
    - Update `list_billet_metadata` to read the `tags` field
    - Handle the case where `tags` attribute is absent (default to empty vec)
    - _Requirements: 1.1_

  - [x] 1.2 Update all existing usages of `BilletMetadata` to include the `tags` field
    - Update all test code constructing `BilletMetadata` across the codebase (`src/domain/admin/billets.rs`, `src/sync/mod.rs`, `src/domain/billet/mod.rs`, `src/domain/admin/policies.rs`)
    - Ensure compilation passes with the new field
    - _Requirements: 1.1_

- [x] 2. Implement tag validation module
  - [x] 2.1 Create tag validation functions in a new file `src/domain/admin/tags.rs`
    - Implement `pub fn validate_tag(tag: &str) -> Result<(), String>` using regex `^[a-zA-Z0-9][a-zA-Z0-9\-_.]*:[a-zA-Z0-9][a-zA-Z0-9\-_.]*$`
    - Implement `pub fn validate_tags(tags: &[String]) -> Result<(), String>` that validates each tag and returns the first invalid one as error
    - Add the module to `src/domain/admin/mod.rs`
    - _Requirements: 1.3, 1.4_

  - [ ]* 2.2 Write property test for tag format validation
    - **Property 1: Tag format validation preserves only valid tags**
    - **Validates: Requirements 1.3, 1.4**
    - Use `proptest` to generate random strings: valid charset+format vs invalid
    - Verify `validate_tag` correctly classifies each

  - [ ]* 2.3 Write unit tests for tag validation edge cases
    - Test valid tags: `env:production`, `team:billing-ops`, `sensitivity:high`, `a:b`
    - Test invalid tags: empty string, no colon, empty key, empty value, invalid characters (`env:prod!`), multiple colons in wrong positions
    - _Requirements: 1.3, 1.4_

- [x] 3. Integrate tags into `BilletCrudService`
  - [x] 3.1 Update `BilletCrudService::create` to accept and validate tags
    - Add `tags: Vec<String>` parameter to the `create` method signature
    - Call `validate_tags` before persistence; return a new error variant on failure
    - Add `InvalidTags(String)` variant to `BilletCrudError`
    - Pass tags through to `BilletMetadata` when constructing the record
    - _Requirements: 1.2, 1.3, 1.4_

  - [x] 3.2 Update `BilletCrudService::update` to accept and validate optional tags
    - Add `tags: Option<Vec<String>>` parameter to the `update` method signature
    - Validate tags if present; merge into existing metadata using the same pattern as other optional fields
    - _Requirements: 1.2, 1.3, 1.4_

  - [x] 3.3 Update `BilletCrudService::get` and `get_with_policies` to return tags
    - Ensure `BilletWithPolicies` struct includes a `tags: Vec<String>` field
    - Populate from metadata
    - _Requirements: 1.5_

  - [x] 3.4 Add `quartermaster-guardrails` to protected billet deletion list
    - Update `delete` and `delete_cascade` methods to check for both `quartermaster-admin` AND `quartermaster-guardrails`
    - Return `ProtectedBillet` error for both
    - _Requirements: 3.2_

  - [ ]* 3.5 Write property test for protected billet deletion invariant
    - **Property 3: Protected billet deletion invariant**
    - **Validates: Requirements 3.2**
    - Use `proptest` to generate random caller contexts; attempt deletion of protected billets; verify always rejected

  - [ ]* 3.6 Write unit tests for BilletCrudService tag integration
    - Test create with valid tags succeeds
    - Test create with invalid tags returns error
    - Test update with valid tags succeeds
    - Test delete of `quartermaster-guardrails` returns ProtectedBillet error
    - _Requirements: 1.2, 1.3, 1.4, 3.2_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement guardrail policy validation (forbid-only enforcement)
  - [x] 5.1 Add `validate_forbid_only` method to `PolicyCrudService` in `src/domain/admin/policies.rs`
    - Parse the Cedar statement into a `PolicySet`
    - Iterate over `policy_set.policies()` and check `policy.effect()`
    - If any policy has `permit` effect, return `PolicyCrudError::InvalidStatement` with message: "guardrail policies must be forbid-only; permit policies are not allowed on the quartermaster-guardrails billet"
    - Accept `forbid` policies with `when` and `unless` clauses
    - _Requirements: 3.3, 5.1, 5.2, 5.3, 5.4_

  - [x] 5.2 Integrate forbid-only validation into `create` and `update` methods
    - When `billet_name == "quartermaster-guardrails"`, call `validate_forbid_only` before other validations
    - _Requirements: 5.1, 5.2_

  - [x] 5.3 Bypass resource scope validation for `quartermaster-guardrails`
    - In the `create` and `update` methods, skip `validate_resource_scope` when `billet_name == "quartermaster-guardrails"`
    - _Requirements: 3.4_

  - [ ]* 5.4 Write property test for forbid-only policy validation
    - **Property 4: Forbid-only policy validation**
    - **Validates: Requirements 3.3, 5.1, 5.2, 5.3, 5.4**
    - Generate random Cedar forbid statements (with/without when/unless); verify accepted
    - Generate permit statements; verify rejected

  - [ ]* 5.5 Write property test for resource scope bypass
    - **Property 5: Guardrail policies bypass resource scope validation**
    - **Validates: Requirements 3.4**
    - Generate random Cedar forbid statements with diverse resource scopes (unconstrained, referencing other billets, conditioning on resource.tags); verify accepted for `quartermaster-guardrails`

  - [ ]* 5.6 Write unit tests for guardrail policy validation
    - Test forbid policy accepted on guardrails billet
    - Test forbid+when accepted
    - Test forbid+unless accepted
    - Test permit rejected with correct error message
    - Test mixed forbid+permit rejected
    - Test unconstrained resource scope accepted for guardrails
    - _Requirements: 3.3, 3.4, 5.1, 5.2, 5.3, 5.4_

- [x] 6. Implement `PolicySyncService` billet tag caching
  - [x] 6.1 Add billet metadata cache and `billet_tags` method to `PolicySyncService` in `src/sync/mod.rs`
    - Add a `billet_metadata: Vec<BilletMetadata>` field to `PolicySyncState`
    - Store the full `list_billet_metadata()` result during sync
    - Add `pub async fn billet_tags(&self, billet_name: &str) -> Vec<String>` method that looks up tags from cached metadata
    - _Requirements: 2.3_

  - [ ]* 6.2 Write unit tests for billet_tags method
    - Test returns correct tags for existing billet
    - Test returns empty vec for unknown billet
    - _Requirements: 2.3_

- [x] 7. Enrich Billet entities with tags in `CedarAuthorizer`
  - [x] 7.1 Create `build_billet_entity` helper function in `src/cedar/mod.rs`
    - Accept `name: &str` and `tags: &[String]` parameters
    - Construct a Cedar `Entity` with `tags` attribute as `Set<String>`
    - Replace existing `Entity::new_no_attrs(...)` calls for billet entities
    - _Requirements: 2.1, 2.2, 2.4_

  - [x] 7.2 Update `batch_is_authorized` to use enriched billet entities
    - Add a `billet_tags: &HashMap<String, Vec<String>>` parameter (name → tags map) to accept tags from the caller
    - Replace `Entity::new_no_attrs(resource_uid, HashSet::new())` with `build_billet_entity(resource_name, tags.get(name).unwrap_or(&vec![]))`
    - Tests in 7.x use inline/mock tag data — the real `PolicySyncService` source is wired in Task 11.1
    - _Requirements: 2.1_

  - [x] 7.3 Update `batch_is_authorized_entity` to use enriched billet entities
    - Add a `billet_tags: &HashMap<String, Vec<String>>` parameter (same pattern as 7.2)
    - Replace `Entity::new_no_attrs(...)` with `build_billet_entity(...)` for resource billet entities
    - _Requirements: 2.1_

  - [x] 7.4 Update `is_authorized_admin` to use enriched billet entities for both principal and resource
    - Add a `billet_tags: &HashMap<String, Vec<String>>` parameter
    - Enrich the resource billet entity with tags (required for guardrails like `resource.tags.contains("immutable:true")`)
    - Enrich the principal billet entity with tags (for consistency per design decision)
    - _Requirements: 2.1_

  - [ ]* 7.5 Write property test for tag round-trip (entity construction)
    - **Property 2: Tag persistence round-trip**
    - **Validates: Requirements 1.1, 2.1, 2.2**
    - Generate random valid tag sets; verify entity construction produces matching tags attribute

  - [ ]* 7.6 Write property test for deny-overrides (guardrail forbid always wins)
    - **Property 6: Deny-overrides — guardrail forbid always wins**
    - **Validates: Requirements 4.1, 4.2, 4.3**
    - Generate random permit+forbid policy combinations targeting the same resource; evaluate; verify deny decision

  - [ ]* 7.7 Write unit tests for billet entity enrichment
    - Test billet entity has tags attribute when tags present
    - Test billet entity has empty tags set when no tags
    - Test guardrail forbid policy denies despite permit policy on same resource
    - _Requirements: 2.1, 2.2, 4.1, 4.2, 4.3_

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement bootstrap service for system billets
  - [x] 9.1 Create `bootstrap_system_billets` function
    - Create a new file `src/domain/bootstrap.rs` (or add to an existing module)
    - Implement `pub async fn bootstrap_system_billets(dynamo_client: &dyn DynamoClient) -> Result<(), DynamoError>`
    - For each system billet (`quartermaster-guardrails`, `quartermaster-admin`): call `get_billet_metadata`; if absent, create with expected description, tags `["system:true"]`, and empty role/SA lists
    - If already exists, no action taken (idempotent)
    - Register module in `src/domain/mod.rs`
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 9.2 Wire `bootstrap_system_billets` into `main.rs` startup
    - Call after DynamoDB client initialization but before PolicySyncService starts
    - Log success/failure; do not block startup on failure (warn and continue)
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ]* 9.3 Write property test for bootstrap idempotence
    - **Property 7: Bootstrap idempotence**
    - **Validates: Requirements 8.1, 8.2, 8.3**
    - Generate random initial states (system billets present or absent); run bootstrap twice; verify convergence and stability

  - [ ]* 9.4 Write unit tests for bootstrap
    - Test creates both billets when neither exists
    - Test idempotent when both already exist
    - Test creates only missing one when one exists
    - Test tags include `system:true`
    - _Requirements: 8.1, 8.2, 8.3_

- [x] 10. Update Admin API handlers for tags
  - [x] 10.1 Add `tags` field to API request/response structs in `src/handler/admin_billets.rs`
    - Add `tags: Vec<String>` (with `#[serde(default)]`) to `CreateBilletRequest`
    - Add `tags: Option<Vec<String>>` to `UpdateBilletRequest`
    - Add `tags: Vec<String>` to `BilletMetadataResponse`
    - _Requirements: 1.2, 1.5_

  - [x] 10.2 Wire tags through handler functions
    - Pass `body.tags` to `billet_crud_service.create(...)` in `create_billet` handler
    - Pass `body.tags` to `billet_crud_service.update(...)` in `update_billet` handler
    - Include `tags` in `BilletMetadataResponse` construction from metadata
    - Map `BilletCrudError::InvalidTags` to `DomainError::invalid_request` in `map_billet_error`
    - _Requirements: 1.2, 1.4, 1.5_

  - [ ]* 10.3 Write unit tests for admin API handlers with tags
    - Test create request with valid tags returns tags in response
    - Test create request with invalid tags returns 400
    - Test get response includes tags
    - Test update with tags field works correctly
    - _Requirements: 1.2, 1.4, 1.5_

- [x] 11. Wire `CedarAuthorizer` to `PolicySyncService` for tag lookups
  - [x] 11.1 Update `CedarAuthorizer` to resolve tags from `PolicySyncService`
    - Add `policy_sync: Arc<PolicySyncService>` field to `CedarAuthorizer`
    - Update constructor and all instantiation sites (`main.rs`, tests)
    - In each evaluation method (`batch_is_authorized`, `batch_is_authorized_entity`, `is_authorized_admin`), build the `HashMap<String, Vec<String>>` from `policy_sync.billet_tags(name)` and pass it to the tag-accepting methods from Task 7
    - This replaces the inline/mock tag data used during Task 7 development with the real cache-backed source
    - _Requirements: 2.1, 2.3_

  - [ ]* 11.2 Write integration-style unit test for end-to-end guardrail evaluation
    - Create a billet with tags → create a guardrail forbid policy conditioning on `resource.tags` → evaluate `assumeBillet` → verify deny decision
    - _Requirements: 4.1, 4.2, 4.3_

- [x] 12. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document using `proptest`
- Unit tests validate specific examples and edge cases
- The implementation language is Rust (matching the existing codebase)
