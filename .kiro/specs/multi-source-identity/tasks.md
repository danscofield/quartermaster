# Implementation Plan: Multi-Source Identity & Unified Billet Resolution

## Overview

This plan implements multi-source identity support for Quartermaster, extending the identity validation layer from SPIRE-only to support four identity sources (SPIRE SVIDs, corporate OIDC tokens, AWS presigned STS, GCP identity tokens). All sources converge on the same Cedar policy engine for billet resolution, with an optional implicit billet mapping layer for OIDC IdP sources.

The implementation proceeds bottom-up: core types and configuration first, then source-specific validators, entity construction, implicit billet mapping, and finally the dispatcher and handler integration that wires everything together.

## Tasks

- [x] 1. Define core identity types and configuration
  - [x] 1.1 Create `src/domain/identity/mod.rs` with the `AuthenticatedIdentity` enum and source-specific identity structs (`SpireIdentity`, `OidcIdentity`, `AwsStsIdentity`, `GcpIdentity`)
    - Define the enum with four variants carrying source-specific claims
    - `OidcIdentity` uses `claims: HashMap<String, Vec<String>>` (keyed by claim name) instead of separate `groups` + `additional_claims` fields
    - Add `IdentityError` enum for validation failures
    - Include `Display` and `Error` impls
    - _Requirements: 1.1, 3.1_

  - [x] 1.2 Add `IdentityConfig`, `OidcSourceConfig`, `AwsStsSourceConfig`, `GcpSourceConfig`, and `ImplicitClaimConfig` to `src/config/mod.rs` (or a new identity config sub-module)
    - Make SPIRE optional (`Option<SpireSourceConfig>`)
    - Support multiple OIDC sources as `Vec<OidcSourceConfig>`
    - Include `implicit_claims` with `claim`, `billet_prefix`, `in_tokens` fields
    - _Requirements: 1.1, 1.2_

  - [x] 1.3 Implement `IdentityConfig` validation: unique prefixes, valid issuer URLs, unique billet_prefixes, prefix regex pattern `[a-z0-9][a-z0-9-]*`, at least one source configured
    - Write a `validate()` method on `IdentityConfig` returning `Result<(), ConfigError>`
    - _Requirements: 1.3_

  - [ ]* 1.4 Write property test for configuration validation (Property 1)
    - **Property 1: Configuration Validation Correctness**
    - Generate random `IdentityConfig` instances with controlled validity dimensions (duplicate prefixes, invalid URLs, empty sources, bad regex patterns)
    - Assert: validation rejects if and only if one of the defined invalid conditions holds
    - **Validates: Requirements 1.3**

- [x] 2. Implement subject formatting and identity claim construction
  - [x] 2.1 Create `src/domain/identity/subject.rs` with the `format_subject` function
    - SPIRE → literal SPIFFE ID
    - OIDC → `human:<email>`
    - AWS STS → `aws:<account_id>:<role_name>`
    - GCP → `gcp:<project_id>:<email>`
    - _Requirements: 6.6_

  - [ ]* 2.2 Write property test for subject formatting (Property 5)
    - **Property 5: Subject Formatting Correctness**
    - Generate random `AuthenticatedIdentity` variants, verify format patterns and injectivity (distinct identities → distinct subjects)
    - **Validates: Requirements 6.6**

  - [x] 2.3 Create `src/domain/identity/claims.rs` with `build_identity_claim` function
    - Construct the `identity` JSON claim with `type` field and source-specific fields
    - SPIRE → `type: "workload"`, `spiffe_id`
    - OIDC → `type: "human"`, `email`, `idp`, `groups`
    - AWS STS → `type: "aws_role"`, `account_id`, `role_arn`
    - GCP → `type: "gcp_workload"`, `project_id`, `email`
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 2.4 Write property test for identity claim construction (Property 6)
    - **Property 6: Identity Claim Construction**
    - Generate random identities, build claims, verify all source-specific fields are present and `type` matches
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement OIDC IdP token validation
  - [x] 4.1 Create `src/domain/identity/oidc.rs` implementing the `OidcValidator` trait
    - Match the token's `iss` claim against configured IdP issuer URLs
    - Verify signature against the IdP's cached JWKS
    - Verify `aud` matches one of `client_ids`
    - Verify token has not expired
    - Extract email, subject, and all configured claim names into `claims: HashMap<String, Vec<String>>`
    - Return `OidcIdentity` with `idp_prefix` set from matched config
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [ ]* 4.2 Write property test for OIDC validation (Property 2)
    - **Property 2: OIDC Validation Correctness**
    - Generate random OIDC JWTs with controlled validity: issuer match, signature match, audience match, expiry
    - Assert: validation accepts if and only if all four conditions hold
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**

- [x] 5. Implement JwksManager for multi-source key management
  - [x] 5.1 Create `src/domain/identity/jwks.rs` with `JwksManager` struct
    - Manage JWKS for multiple sources (SPIRE trust bundle, each OIDC IdP, Google JWKS)
    - Each source has independent `refresh_interval` and `max_staleness` threshold
    - Implement periodic refresh via background task
    - Continue using cached keys on refresh failure; reject after `max_staleness`
    - _Requirements: 2.7, 2.8, 2.9_

  - [ ]* 5.2 Write unit tests for JWKS staleness logic
    - Test refresh failure → continue with cached keys
    - Test staleness threshold → rejection with 503
    - _Requirements: 2.8, 2.9_

- [ ] 6. Implement AWS presigned STS validation
  - [x] 6.1 Create `src/domain/identity/aws_sts.rs` with ARN parsing module
    - Parse IAM role ARNs: `arn:aws:iam::<account_id>:role/<path>/<role_name>`
    - Parse assumed role ARNs: `arn:aws:sts::<account_id>:assumed-role/<role_name>/<session_name>`
    - Extract `account_id`, `role_name`, `role_path`, `session_name`
    - _Requirements: 8.3_

  - [ ]* 6.2 Write property test for ARN parsing (Property 10)
    - **Property 10: ARN Parsing**
    - Generate random valid IAM/STS ARNs, verify correct extraction of components
    - Generate invalid ARNs, verify rejection
    - **Validates: Requirements 8.3**

  - [x] 6.3 Implement presigned STS URL validation and calling logic
    - Validate URL host is `sts.amazonaws.com` or `sts.<region>.amazonaws.com`
    - Verify `Action=GetCallerIdentity` in query params
    - Check `X-Amz-Date` + `X-Amz-Expires` for expiry
    - Call the presigned URL and parse GetCallerIdentity XML response
    - Extract `Account`, `Arn`, `UserId` from response
    - Apply `allowed_accounts` filter if configured
    - Return `AwsStsIdentity`
    - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.6_

  - [ ]* 6.4 Write property test for presigned STS URL validation (Property 11)
    - **Property 11: Presigned STS URL Validation**
    - Generate random URLs with controlled validity: host pattern, Action param, expiry
    - Assert: accepted if and only if host matches, Action correct, and not expired
    - **Validates: Requirements 8.5, 8.6**

- [ ] 7. Implement GCP identity token validation
  - [x] 7.1 Create `src/domain/identity/gcp.rs` implementing the `GcpValidator` trait
    - Verify token signature against Google's JWKS (via JwksManager)
    - Verify `aud` matches configured Quartermaster audience
    - Verify token not expired
    - Extract: `sub`, `email`, `google.compute_engine.project_id`, `google.compute_engine.zone`
    - Apply `allowed_projects` filter if configured
    - Return `GcpIdentity`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [ ]* 7.2 Write property test for GCP token validation (Property 3)
    - **Property 3: GCP Token Validation Correctness**
    - Generate random GCP JWTs with controlled validity: signature, audience, expiry
    - Assert: accepted if and only if signature valid, audience matches, and not expired
    - Verify required claims correctly extracted on success
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.5**

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement multi-source entity builder and Cedar schema extensions
  - [x] 9.1 Create `src/domain/identity/entity.rs` with `MultiSourceEntityBuilder`
    - Build `HumanIdentity` Cedar entity from `OidcIdentity`: set `email`, `idp_prefix`, flatten all values from `claims` map into `groups` Set
    - Build `AwsRoleIdentity` Cedar entity from `AwsStsIdentity` (account_id, role_arn, role_name, role_path)
    - Build `GcpIdentity` Cedar entity from `GcpIdentity` (project_id, email, zone)
    - Delegate SPIRE to existing `EntityBuilder`
    - Include `source_type` in Cedar context for all variants
    - _Requirements: 3.2, 3.3, 3.4, 3.5, 3.6, 7.1, 7.2, 7.3, 7.4_

  - [ ]* 9.2 Write property test for entity construction (Property 4)
    - **Property 4: Entity Construction Preserves Attributes**
    - Generate random `AuthenticatedIdentity` variants, build Cedar entities, verify all attributes preserved without loss or mutation
    - Verify `source_type` context field matches identity variant
    - **Validates: Requirements 3.3, 3.4, 3.5, 3.6**

  - [x] 9.3 Update Cedar schema with new entity types (`HumanIdentity`, `AwsRoleIdentity`, `GcpIdentity`) and extend `assumeBillet` action's `principalTypes`
    - Add `source_type` to the Cedar context record
    - Extend admin actions to accept new principal types
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 10. Implement implicit billet mapping
  - [x] 10.1 Create `src/domain/identity/implicit.rs` with `ImplicitBilletMapper`
    - Derive billets from configured claim mappings: `<billet_prefix>:<claim_value>`
    - Separate results by `in_tokens` flag: `token_billets` vs `all_billets`
    - Support multiple claim mappings per IdP (independent sets unioned)
    - _Requirements: 4.1, 4.2, 4.3, 4.7_

  - [ ]* 10.2 Write property test for implicit billet derivation (Property 7)
    - **Property 7: Implicit Billet Derivation**
    - Generate random claim mappings and claim values (lists of strings)
    - Assert: exactly one billet per claim value per mapping, formatted as `<billet_prefix>:<claim_value>`
    - Multiple mappings produce independent sets that are unioned
    - **Validates: Requirements 4.1, 4.7**

  - [x] 10.3 Implement token billet assembly logic: Cedar billets minus reserved prefixes, union with implicit token billets
    - Strip Cedar-evaluated billets whose names start with any reserved implicit prefix
    - Union remaining Cedar billets with implicit billets where `in_tokens = true`
    - _Requirements: 4.5, 5.1, 5.2, 5.4_

  - [ ]* 10.4 Write property test for token billet assembly (Property 8)
    - **Property 8: Token Billet Assembly**
    - Generate random Cedar billet sets, implicit billet results (with `in_tokens` flags), and reserved prefix sets
    - Assert: final token billets = (Cedar billets MINUS reserved prefix matches) UNION (implicit billets where `in_tokens = true`)
    - **Validates: Requirements 4.2, 4.5, 5.1, 5.2, 5.4**

- [x] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Generalize audit events and cache/rate-limit keys
  - [x] 12.1 Refactor `AuditEvent` in `src/domain/audit/mod.rs`
    - Replace `spiffe_id: String` with `subject: String` + `source_type: String`
    - Add `implicit_billets: Vec<String>` and `cedar_billets: Vec<String>` fields
    - Add `IdentityAuditDetails` enum with source-specific variants
    - Update `TracingAuditLogger` to emit the new fields
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [ ]* 12.2 Write property test for audit event construction (Property 9)
    - **Property 9: Audit Event Construction**
    - Generate random `AuthenticatedIdentity` and resolution results (Cedar + implicit billets)
    - Assert: audit event has correct `source_type`, formatted `subject`, separated billets, and matching identity details
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

  - [x] 12.3 Generalize cache key to `subject + audience` (update `Cache` trait usage in resolver)
    - Use formatted `sub` claim as cache key instead of raw `spiffe_id`
    - _Requirements: Integration point 5_

  - [x] 12.4 Generalize rate limiter key to per-subject (update `Limiter` trait usage)
    - Accept the formatted subject string instead of raw SPIFFE ID
    - _Requirements: Integration point 6_

- [ ] 13. Implement IdentityDispatcher and integrate with token exchange handler
  - [x] 13.1 Create `src/domain/identity/dispatcher.rs` with `IdentityDispatcher` implementation
    - Route by `subject_token_type` to appropriate validator
    - `urn:ietf:params:oauth:token-type:jwt` → SPIRE validator
    - `urn:quartermaster:token-type:oidc` → OIDC validator
    - `urn:quartermaster:token-type:aws-presigned-sts` → AWS STS validator
    - `urn:quartermaster:token-type:gcp-identity` → GCP validator
    - Return `IdentityError` for unknown token types
    - _Requirements: 1.4_

  - [x] 13.2 Refactor `src/handler/token.rs` to use `IdentityDispatcher`
    - Replace hardcoded SVID validation with dispatcher call
    - Accept all `subject_token_type` values
    - After dispatch, route through `MultiSourceEntityBuilder` → Cedar evaluation → implicit mapping → token assembly
    - Include `identity` claim and source-formatted `sub` in issued JWT
    - Wire implicit billet mapper for OIDC sources
    - Use generalized audit event construction
    - _Requirements: 1.4, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 13.3 Update `AppState` in `src/server/mod.rs` to hold the new components (`IdentityDispatcher`, `JwksManager`, `ImplicitBilletMapper`, `MultiSourceEntityBuilder`)
    - Initialize components based on `IdentityConfig`
    - Make SPIRE optional — skip SPIRE initialization if not configured
    - _Requirements: Integration point 9_

  - [x] 13.4 Update admin API billet creation endpoint to reject reserved implicit prefixes
    - Check billet name against reserved prefix set before allowing creation
    - Return HTTP 400 if prefix is reserved
    - _Requirements: 5.3_

- [x] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 15. Integration tests for end-to-end multi-source flows
  - [ ]* 15.1 Write integration tests for OIDC token exchange end-to-end flow
    - Mock OIDC IdP JWKS endpoint
    - Submit OIDC token → verify identity claim, subject format, billets in response
    - Verify implicit billets appear or are stripped based on `in_tokens` flag
    - _Requirements: 2.1, 4.2, 6.3_

  - [ ]* 15.2 Write integration tests for AWS presigned STS token exchange
    - Mock STS endpoint response
    - Submit presigned URL → verify identity claim, subject format, Cedar evaluation
    - _Requirements: 8.1, 8.2, 6.4_

  - [ ]* 15.3 Write integration tests for GCP identity token exchange
    - Mock Google JWKS endpoint
    - Submit GCP token → verify identity claim, subject format, Cedar evaluation
    - _Requirements: 9.1, 9.4, 6.5_

  - [ ]* 15.4 Write integration test for multi-source concurrent operation
    - Single Quartermaster instance handling requests from different source types
    - Verify source isolation (one source failure doesn't affect others)
    - _Requirements: 1.1, 3.1_

- [x] 16. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate the 11 universal correctness properties defined in the design
- The implementation language is Rust, matching the existing codebase and design document
- `proptest` is already in dev-dependencies — no additional test framework setup needed
- The existing SPIRE validation module (`src/domain/svid/`) will be wrapped by the new dispatcher rather than deleted, preserving backward compatibility
