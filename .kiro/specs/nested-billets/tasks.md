# Implementation Plan: Nested Billets API & Scoped Admin Authorization

## Overview

This plan restructures the Quartermaster admin API to nest policies under billets, updates the DynamoDB schema to use composite keys (billet_name PK, policy_id SK), introduces cascade deletion, billet metadata updates, resource scope validation, and scoped admin authorization. The implementation proceeds bottom-up: persistence layer first, then domain services, then handlers and routing.

## Tasks

- [x] 1. Update DynamoDB layer for composite-key policies
  - [x] 1.1 Update `PolicyRecord` struct to include `billet_name` field and change `DynamoClient` trait signatures
    - Add `billet_name: String` to `PolicyRecord` in `src/dynamo/mod.rs`
    - Change `create_policy` to accept `billet_name` as first parameter
    - Change `update_policy` and `delete_policy` to accept `billet_name` + `policy_id` composite key
    - Add `get_policy(billet_name, policy_id)` method
    - Add `list_policies_for_billet(billet_name)` method (DynamoDB Query on PK)
    - Rename `list_policies` to `scan_all_policies` for clarity
    - Add `delete_policies_for_billet(billet_name)` method returning count of deleted items
    - Update `MockDynamoClient` expectations accordingly
    - _Requirements: 9.1, 9.3, 9.4_

  - [x] 1.2 Implement `AwsDynamoClient` methods for new composite-key operations
    - Implement `list_policies_for_billet` using DynamoDB Query (not Scan) with `billet_name` as PK
    - Implement `get_policy` using GetItem with composite key
    - Implement `delete_policies_for_billet` using Query + BatchWriteItem with retry logic (up to 3 retries with exponential backoff for unprocessed items)
    - Update `create_policy`, `update_policy`, `delete_policy` to use composite key (PK: billet_name, SK: policy_id)
    - Rename `list_policies` implementation to `scan_all_policies`
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [ ]* 1.3 Write unit tests for new DynamoClient trait methods
    - Test mock expectations for `list_policies_for_billet`, `get_policy`, `delete_policies_for_billet`
    - Test composite key structure in mock calls
    - _Requirements: 9.1, 9.3, 9.4_

- [x] 2. Update PolicySyncService to use billets table as source of truth
  - [x] 2.1 Change `sync_once` to scan billets table for known billet set
    - Replace regex-based `extract_billet_names` with `list_billet_metadata` call
    - Update `sync_once` to call `scan_all_policies()` (renamed from `list_policies`)
    - Update `sync_once` to call `list_billet_metadata()` and build `known_billets` from that result
    - Remove the `extract_billet_names` function and its regex dependency
    - Handle failure of either scan independently (preserve last state on failure)
    - _Requirements: 10.2, 10.3_

  - [ ]* 2.2 Write property test for known billets derived from billets table
    - **Property 6: Known billets derived from billets table, not policy scopes**
    - Generate random billets in billets table and different billets referenced in policy scopes
    - After sync, assert known_billets == billets table set (not policy-derived set)
    - **Validates: Requirements 10.2, 10.3**

  - [ ]* 2.3 Write unit tests for updated PolicySyncService
    - Test sync_once with empty billets table returns empty known_billets
    - Test sync_once with billets that don't appear in policies still shows in known_billets
    - Test failure of list_billet_metadata preserves previous known_billets
    - _Requirements: 10.2, 10.3_

- [x] 3. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement resource scope validation
  - [x] 4.1 Implement `validate_resource_scope` function in `PolicyCrudService`
    - Parse Cedar statement into `PolicySet`
    - For each policy with `action == Action::"assumeBillet"`, inspect the resource constraint
    - Reject if resource scope is unconstrained (bare `resource`) for assumeBillet actions
    - Reject if resource scope references a billet name different from the owning billet
    - Accept if resource scope is `== Billet::"<owning_billet_name>"`
    - Return `PolicyCrudError::InvalidResourceScope(msg)` on mismatch
    - _Requirements: 4.5, 7.3_

  - [ ]* 4.2 Write property test for resource scope validation
    - **Property 4: Resource scope validation rejects mismatched billet references**
    - Generate Cedar statements with parameterized resource scopes: matching billet, different billet, unconstrained
    - Assert correct accept/reject for each case
    - **Validates: Requirements 4.5, 7.3**

  - [ ]* 4.3 Write unit tests for resource scope validation edge cases
    - Test valid statement with matching billet → accept
    - Test statement referencing different billet → reject
    - Test unconstrained resource on assumeBillet action → reject
    - Test non-assumeBillet action with unconstrained resource → accept
    - Test multiple policies in one statement (mixed valid/invalid)
    - _Requirements: 4.5, 7.3_

- [x] 5. Refactor PolicyCrudService for billet-scoped operations
  - [x] 5.1 Update `PolicyCrudService` to accept `billet_name` in all operations
    - Add `BilletNotFound` and `InvalidResourceScope` variants to `PolicyCrudError`
    - Change `create` to accept `billet_name`, validate billet exists via `get_billet_metadata`, validate resource scope, then write with composite key
    - Add `list_for_billet(billet_name)` method that calls `list_policies_for_billet`
    - Add `get(billet_name, policy_id)` method
    - Change `update` to accept `billet_name` + `policy_id`, validate resource scope, then update with composite key
    - Change `delete` to accept `billet_name` + `policy_id`
    - Add `DynamoClient` dependency for billet existence check (or accept it as constructor param alongside existing client)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 5.1, 6.1, 7.1, 7.2, 7.3, 7.4, 8.1_

  - [ ]* 5.2 Write property test for policy list isolation by billet partition
    - **Property 5: Policy listing is isolated by billet partition**
    - Generate policies across 2+ billets, list for one billet, assert only that billet's policies returned
    - **Validates: Requirements 5.1, 9.3**

  - [ ]* 5.3 Write unit tests for PolicyCrudService billet-scoped operations
    - Test create with non-existent billet → BilletNotFound error
    - Test create with valid billet and valid statement → success
    - Test create with invalid resource scope → InvalidResourceScope error
    - Test list_for_billet returns only policies for that billet
    - Test get returns correct policy
    - Test update with mismatched resource scope → error
    - Test delete with non-existent policy → NotFound
    - _Requirements: 4.1–4.7, 5.1–5.4, 6.1–6.3, 7.1–7.6, 8.1–8.4_

- [x] 6. Update BilletCrudService for metadata update and cascade delete
  - [x] 6.1 Implement `update` method for billet metadata
    - Accept optional fields: `description`, `associated_aws_roles`, `associated_gcp_sas`
    - Fetch existing metadata, merge provided fields, write back
    - Return 404 if billet does not exist
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 6.2 Implement `get_with_policies` method
    - Fetch billet metadata from billets table
    - Fetch policies via `list_policies_for_billet`
    - Return combined `BilletWithPolicies` struct
    - Return 404 if billet does not exist
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 6.3 Implement `delete_cascade` method
    - Check protected billet guard (reject `quartermaster-admin`)
    - Check billet exists (return 404 if not)
    - Delete all policies for billet via `delete_policies_for_billet`
    - Delete billet metadata record
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 6.4 Update `list` method to use only billets table as source of truth
    - Remove merging with policy-derived billet names
    - List only from `list_billet_metadata`
    - Remove `has_metadata` field (all listed billets have metadata now)
    - _Requirements: 10.1_

  - [ ]* 6.5 Write property test for metadata update field preservation
    - **Property 1: Metadata update preserves provided fields and leaves others unchanged**
    - Generate random initial billet state and random subset of update fields
    - Assert provided fields changed, un-provided fields retained
    - **Validates: Requirements 1.1, 1.2**

  - [ ]* 6.6 Write property test for get billet with policies
    - **Property 2: Get billet returns metadata and all attached policies**
    - Generate 0..20 random policies under a billet, call get_with_policies
    - Assert response has correct metadata and exactly N policies
    - **Validates: Requirements 2.1, 2.2, 2.3**

  - [ ]* 6.7 Write property test for cascade delete
    - **Property 3: Cascade delete removes billet and all attached policies**
    - Generate 0..20 policies under a billet, call delete_cascade
    - Assert subsequent gets for billet and all policies return not-found
    - **Validates: Requirements 3.1, 3.2**

- [x] 7. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Update handler layer and routing
  - [x] 8.1 Add policy CRUD handlers to `admin_billets` module
    - Add `create_policy` handler at `POST /admin/billets/{name}/policies`
    - Add `list_policies` handler at `GET /admin/billets/{name}/policies`
    - Add `get_policy` handler at `GET /admin/billets/{name}/policies/{id}`
    - Add `update_policy` handler at `PUT /admin/billets/{name}/policies/{id}`
    - Add `delete_policy` handler at `DELETE /admin/billets/{name}/policies/{id}`
    - Each handler extracts `name` (and `id` where applicable) from path
    - Each handler authenticates with the owning billet as Cedar resource
    - _Requirements: 4.1, 4.7, 4.8, 5.1, 6.1, 7.1, 7.7, 8.1, 8.4, 12.1_

  - [x] 8.2 Add `update_billet` handler at `PUT /admin/billets/{name}`
    - Accept `UpdateBilletRequest` body with optional fields
    - Authenticate with `updateBillet` action and target billet as resource
    - Delegate to `BilletCrudService::update`
    - Return 200 with updated metadata on success
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 8.3 Update `get_billet` handler to return policies
    - Change GET `/admin/billets/{name}` to call `get_with_policies` instead of `get`
    - Return `BilletWithPolicies` response (metadata + policies array)
    - Use `readBillet` auth action
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 8.4 Update `delete_billet` handler for cascade delete
    - Change DELETE `/admin/billets/{name}` to call `delete_cascade`
    - Use `deleteBillet` auth action with target billet as resource
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.6_

  - [x] 8.5 Update router to register nested policy routes and PUT billet route
    - Register `PUT /admin/billets/{name}` → `update_billet`
    - Register `POST /admin/billets/{name}/policies` → `create_policy`
    - Register `GET /admin/billets/{name}/policies` → `list_policies`
    - Register `GET /admin/billets/{name}/policies/{id}` → `get_policy`
    - Register `PUT /admin/billets/{name}/policies/{id}` → `update_policy`
    - Register `DELETE /admin/billets/{name}/policies/{id}` → `delete_policy`
    - Remove `/admin/policies` and `/admin/policies/{id}` routes
    - _Requirements: 12.2_

  - [x] 8.6 Remove `admin_policies` handler module
    - Delete `src/handler/admin_policies.rs`
    - Remove `pub mod admin_policies;` from `src/handler/mod.rs`
    - _Requirements: 12.1_

  - [ ]* 8.7 Write integration tests for handler routes using `axum-test`
    - Test POST `/admin/billets/{name}/policies` → 201 on success, 404 on missing billet, 400 on bad Cedar
    - Test GET `/admin/billets/{name}/policies` → 200 with array
    - Test GET `/admin/billets/{name}/policies/{id}` → 200 on found, 404 on missing
    - Test PUT `/admin/billets/{name}/policies/{id}` → 200 on success, 400 on scope mismatch
    - Test DELETE `/admin/billets/{name}/policies/{id}` → 204 on success, 404 on missing
    - Test PUT `/admin/billets/{name}` → 200 on success, 404 on missing billet
    - Test DELETE `/admin/billets/{name}` cascade → 204 and policies removed
    - _Requirements: 1.1–1.5, 2.1–2.3, 3.1–3.6, 4.1–4.8, 5.1–5.4, 6.1–6.3, 7.1–7.7, 8.1–8.4_

- [x] 9. Implement scoped admin authorization
  - [x] 9.1 Update all admin handlers to pass target billet as Cedar resource
    - Ensure `create_billet` passes the new billet name as resource for `createBillet` action
    - Ensure `update_billet` passes target billet name for `updateBillet` action
    - Ensure `delete_billet` passes target billet name for `deleteBillet` action
    - Ensure `get_billet` passes target billet name for `readBillet` action
    - Ensure policy handlers pass owning billet name for their respective actions
    - Verify `Authenticator::authenticate` signature supports action + resource parameters
    - _Requirements: 11.1, 11.2, 11.3_

  - [ ]* 9.2 Write property test for scoped admin authorization
    - **Property 7: Scoped Cedar admin policies correctly restrict per-billet access**
    - Generate scoped Cedar policies for random billet names
    - Evaluate against matching and non-matching resources
    - Assert allow on matching billet, deny on other billets
    - **Validates: Requirements 11.1, 11.2**

- [x] 10. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The implementation uses Rust with the existing project tooling (axum, cedar-policy, aws-sdk-dynamodb, proptest, mockall)
