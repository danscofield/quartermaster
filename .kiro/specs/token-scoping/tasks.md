# Implementation Plan: Token Scoping & Billet Discovery

## Overview

Implement opt-in billet scoping for the token exchange endpoint and a new `/billets/me` discovery endpoint. The approach adds two pure functions (`scope_billets`, `parse_requested_billets`), modifies the existing token handler to apply scoping between billet assembly and JWT issuance, and introduces a new discovery handler that reuses the identity/resolution pipeline without issuing credentials.

## Tasks

- [x] 1. Implement `scope_billets` pure function in `src/domain/billet/mod.rs`
  - [x] 1.1 Add `ScopeResult` and `ScopeDenied` structs and the `scope_billets` function
    - Define `ScopeResult { billets: Vec<String> }` and `ScopeDenied { denied: Vec<String> }`
    - Implement `scope_billets(entitled: &[String], requested: &[String]) -> Result<ScopeResult, ScopeDenied>`
    - Use `HashSet` intersection logic: if `requested ⊆ entitled` return Ok with requested set, else return Err with `requested \ entitled`
    - _Requirements: 1.2, 1.3, 1.4, 1.6_

  - [ ]* 1.2 Write property test: billet scoping is set intersection
    - **Property 1: Billet scoping is set intersection**
    - Generate random `entitled: HashSet<String>` and `requested` where `requested ⊆ entitled`
    - Assert `scope_billets` returns Ok and result == requested; result ⊆ entitled
    - **Validates: Requirements 1.2, 1.3, 1.6**

  - [ ]* 1.3 Write property test: denied billets are the set difference
    - **Property 2: Denied billets are the set difference**
    - Generate random `entitled` and `requested` where `requested ⊄ entitled`
    - Assert `scope_billets` returns Err with denied == `requested \ entitled`
    - **Validates: Requirements 1.4**

- [x] 2. Implement `parse_requested_billets` and modify `TokenExchangeForm` in `src/handler/token.rs`
  - [x] 2.1 Add `billets: Option<String>` field to `TokenExchangeForm`
    - Add the optional `billets` field to the existing form struct
    - _Requirements: 1.1_

  - [x] 2.2 Implement `parse_requested_billets` helper function
    - Add `fn parse_requested_billets(raw: &str) -> Option<Vec<String>>`
    - Split on comma, trim each segment, filter empty strings, deduplicate
    - Return `None` for empty/whitespace-only input
    - _Requirements: 1.1_

  - [ ]* 2.3 Write property test: billet parameter parsing round-trip
    - **Property 3: Billet parameter parsing round-trip**
    - Generate random `Vec` of valid billet names (no commas, non-empty, no leading/trailing whitespace)
    - Assert `parse_requested_billets(names.join(","))` produces `Some(names)`
    - **Validates: Requirements 1.1**

  - [ ]* 2.4 Write unit tests for `parse_requested_billets`
    - Test `parse_requested_billets("")` returns `None`
    - Test `parse_requested_billets("  ,  , ")` returns `None`
    - Test `parse_requested_billets("a, b ,c")` returns `Some(["a", "b", "c"])`
    - Test deduplication behavior
    - _Requirements: 1.1_

- [x] 3. Insert scoping logic in `token_exchange` handler
  - [x] 3.1 Add scoping step between billet assembly and JWT issuance
    - Import `scope_billets` from `crate::domain::billet`
    - After step 7 (`assemble_token_billets`), check if `form.billets` is present
    - If present: call `parse_requested_billets`, then `scope_billets` on the result
    - On `ScopeDenied`: return 403 with `insufficient_scope` error listing denied billets
    - On success or absent param: proceed with `scoped_billets`
    - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6_

  - [x] 3.2 Update JWT and cert issuance to use `scoped_billets`
    - Replace `final_billets` with `scoped_billets` in `IssueRequest.billets`
    - Replace `final_billets` with `scoped_billets` in `CertIssueRequest.billets`
    - Ensures cross-credential consistency: both JWT and cert receive identical billet list
    - _Requirements: 3.1, 3.2_

  - [ ]* 3.3 Write property test: cross-credential billet consistency
    - **Property 5: Cross-credential billet consistency**
    - Verify the same billet list is passed to both `IssueRequest.billets` and `CertIssueRequest.billets` when both `billets` and `csr` are present
    - **Validates: Requirements 3.1, 3.2**

  - [ ]* 3.4 Write unit tests for scoped token exchange
    - Test token exchange without `billets` param → full entitled set in JWT
    - Test token exchange with valid `billets` param → only requested billets in JWT
    - Test token exchange with invalid `billets` param → 403 with denied list
    - Test empty/whitespace `billets` param treated as absent
    - _Requirements: 1.2, 1.3, 1.4, 1.5_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement `POST /billets/me` discovery endpoint
  - [x] 5.1 Create `src/handler/billets_discovery.rs` with handler and types
    - Define `BilletDiscoveryForm` with `subject_token` and `subject_token_type` fields
    - Define `BilletDiscoveryResponse` with `billets`, `implicit_billets`, `cedar_billets` fields
    - Implement `billet_discovery` handler: validate identity → rate limit → resolve billets → implicit mapping → assemble → return 200 JSON
    - Return 200 with empty arrays when caller has no entitled billets (no 403)
    - Return 400 for missing `subject_token` or `subject_token_type`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

  - [ ]* 5.2 Write property test: discovery response contains consistent sets
    - **Property 4: Discovery response contains consistent sets**
    - Generate random cedar_billets and implicit_billets
    - Assert `billets` field equals `assemble_token_billets` output; `cedar_billets` and `implicit_billets` match source sets
    - **Validates: Requirements 2.4**

  - [ ]* 5.3 Write unit tests for billet discovery handler
    - Test `/billets/me` with valid identity → 200 with correct JSON structure
    - Test `/billets/me` with no entitled billets → 200 with empty arrays
    - Test `/billets/me` missing `subject_token` → 400
    - Test `/billets/me` missing `subject_token_type` → 400
    - _Requirements: 2.1, 2.3, 2.4, 2.6_

- [x] 6. Register the discovery endpoint in the router
  - [x] 6.1 Add `pub mod billets_discovery;` to `src/handler/mod.rs`
    - Add the module declaration alongside existing handler modules
    - _Requirements: 2.1_

  - [x] 6.2 Register `POST /billets/me` route in `src/server/mod.rs`
    - Add `.route("/billets/me", post(handler::billets_discovery::billet_discovery))` to `build_main_router`
    - _Requirements: 2.1_

- [x] 7. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The `scope_billets` function and `parse_requested_billets` are pure functions — easy to test in isolation before wiring into the handler
