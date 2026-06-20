# Implementation Plan: Quartermaster

## Overview

Quartermaster is a Rust-based workload identity federation broker. Implementation proceeds from foundational infrastructure (config, errors, signing) through domain logic (SVID validation, billet resolution, token/cert issuance) to HTTP handlers and integration wiring. Property-based tests using `proptest` validate the 18 correctness properties defined in the design.

## Tasks

- [x] 1. Project scaffolding and core infrastructure
  - [x] 1.1 Initialize Cargo workspace and dependencies
    - Create `Cargo.toml` with dependencies: axum, tokio, serde, serde_json, chrono, async-trait, jsonwebtoken, rcgen, ring, uuid, tracing, tracing-subscriber, base64, cedar-policy, aws-sdk-dynamodb, aws-config, proptest (dev), axum-test (dev), mockall (dev)
    - Create the directory structure matching the design crate layout (src/config, src/server, src/handler, src/domain/*, src/cedar, src/dynamo, src/sync, src/spireapi, src/signing, src/oidc)
    - Create stub `mod.rs` files for all modules
    - _Requirements: N/A (scaffolding)_

  - [x] 1.2 Implement configuration loading
    - Create `src/config/mod.rs` with `Config`, `SpireConfig`, `DynamoConfig`, `SigningConfig`, `CaConfig`, `CacheConfig`, `RedisConfig`, `RateConfig`, `ServerConfig` structs
    - Implement deserialization from environment variables or TOML file
    - Add validation (non-empty issuer, valid durations, valid algorithm values)
    - DynamoConfig includes: region, policies_table (default: "quartermaster-policies"), billets_table (default: "quartermaster-billets"), policy_sync_interval_secs (default: 30)
    - _Requirements: All (configuration underpins every component)_

  - [x] 1.3 Implement error types and HTTP error mapping
    - Create `src/domain/mod.rs` with `ErrorCode` enum and `DomainError` struct
    - Implement `From<DomainError>` for axum `IntoResponse` producing JSON error responses
    - Map error codes to HTTP status codes (400, 401, 403, 404, 409, 429, 503)
    - Follow OAuth 2.0 error code conventions in JSON body
    - _Requirements: 1.5, 1.6, 1.7, 2.7, 2.8, 3.3, 3.4, 11.2, 15.5_

- [x] 2. Signing key manager
  - [x] 2.1 Implement signing key manager trait and static key backend
    - Create `src/signing/mod.rs` with `SigningManager` trait
    - Create `src/signing/static_key.rs` implementing ES256 static key loading from PEM file
    - Expose `encoding_key()`, `header()` (with kid), `jwks()` (JWK Set JSON), `key_id()`
    - Generate a key ID from the public key thumbprint (SHA-256)
    - _Requirements: 7.2, 7.3, 7.4, 16.2_

- [x] 3. SVID validation
  - [x] 3.1 Implement SVID validator trait and SPIRE-based implementation
    - Create `src/domain/svid/mod.rs` with `Claims` struct, `SvidError` enum, and `Validator` trait
    - Implement validation: decode JWT header, verify signature against SPIRE trust bundle JWKS, check expiry, verify issuer matches configured trust domain, verify audience includes Quartermaster issuer
    - Return typed errors: `SignatureInvalid`, `Expired`, `UnknownTrustDomain`, `InvalidAudience`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 3.2 Write property test for SVID validation correctness
    - **Property 1: SVID Validation Correctness**
    - Generate random JWT payloads, signing keys (some in trust bundle, some not), random expiry times, random issuers/audiences
    - Assert: accepts if and only if (valid sig AND not expired AND issuer matches AND audience includes issuer ID)
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4**

- [x] 4. Token issuance
  - [x] 4.1 Implement token issuer trait and ES256 implementation
    - Create `src/domain/token/mod.rs` with `IssueRequest`, `IssueResponse`, `Claims` structs and `Issuer` trait
    - Implement JWT construction: set iss (config issuer), sub (SPIFFE ID), aud (single audience string), billets array, iat/exp (configured TTL), jti (UUID v4)
    - Sign with `SigningManager`'s encoding key and header
    - Return `IssueResponse` with access_token, issued_token_type, token_type, expires_in
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 10.1, 10.2, 10.3_

  - [x] 4.2 Write property test for JWT issuance round-trip
    - **Property 2: JWT Issuance Round-Trip**
    - Generate random SPIFFE IDs, audiences, billet sets; issue then parse
    - Assert: iss == config issuer, sub == input SPIFFE ID, aud == single audience, billets == input set, exp - iat == TTL
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 10.1, 10.2, 10.3, 14.6**

  - [x] 4.3 Write property test for JWT ID uniqueness
    - **Property 3: JWT ID Uniqueness**
    - Issue N tokens with same inputs, collect all jti values, assert all distinct
    - **Validates: Requirements 4.6**

  - [x] 4.4 Write property test for JWT signature verification round-trip
    - **Property 4: JWT Signature Verification Round-Trip**
    - Issue tokens, retrieve public key from SigningManager JWKS, verify signature succeeds, kid in JWT header matches kid in JWKS
    - **Validates: Requirements 16.1, 16.2, 7.2, 7.3**

- [x] 5. Certificate authority
  - [x] 5.1 Implement certificate authority trait and local CA implementation
    - Create `src/domain/cert/mod.rs` with `CertIssueRequest`, `CertIssueResponse`, `CertError` and `Authority` trait
    - Implement using `rcgen`: parse CSR (DER), verify CSR self-signature, extract public key only (discard Subject/SANs/extensions from CSR)
    - Build certificate: Subject CN = SPIFFE ID, URI SANs = [SPIFFE ID, qm-billet://{trust_domain}/{billet} for each billet], validity = configured TTL, Key Usage = Digital Signature | Key Encipherment, Extended Key Usage = Client Auth + Server Auth, random serial number
    - Sign with CA key, return PEM chain (leaf + intermediate)
    - Implement `chain_pem()` returning CA cert chain for trust bundle endpoint
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 15.1, 15.2, 15.3, 15.4_

  - [x] 5.2 Write property test for certificate construction correctness
    - **Property 5: Certificate Construction Correctness**
    - Generate random key pairs and CSRs (with arbitrary Subject/SANs), random SPIFFE IDs and billet sets
    - Assert: pubkey matches CSR, CN == SPIFFE ID, URI SANs correct, validity == TTL, KU/EKU correct, CSR Subject/SANs discarded
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.9, 15.3, 15.4**

  - [x] 5.3 Write property test for certificate serial uniqueness
    - **Property 6: Certificate Serial Uniqueness**
    - Issue N certificates, collect serial numbers, assert all distinct
    - **Validates: Requirements 5.8**

  - [x] 5.4 Write property test for certificate chain verification round-trip
    - **Property 7: Certificate Chain Verification Round-Trip**
    - Issue certificates, verify chain against CA trust bundle, assert verification succeeds
    - **Validates: Requirements 17.1**

  - [ ] 5.5 Write property test for CSR self-signature verification
    - **Property 15: CSR Self-Signature Verification**
    - Generate valid CSRs and corrupted CSRs (flip bits in signature), assert valid ones accepted and corrupted ones rejected
    - **Validates: Requirements 15.1, 15.2**

- [x] 6. Cache layer
  - [x] 6.1 Implement cache trait and in-memory backend
    - Create `src/domain/cache/mod.rs` with `CacheEntry`, `CacheError`, and `Cache` trait (get, set, delete)
    - Create `src/domain/cache/memory.rs` with `InMemoryCache` using `tokio::sync::RwLock<HashMap>` with timestamp-based TTL expiry
    - On `get`: check if entry exists and stored_at + TTL > now; return None if expired
    - On `set`: store entry with current timestamp and TTL
    - Periodic cleanup of expired entries (lazy or background task)
    - _Requirements: 9.1, 9.2, 9.3, 9.5, 9.6, 9.7, 9.10_

  - [ ] 6.2 Write property test for cache round-trip
    - **Property 9: Cache Round-Trip**
    - Generate random SPIFFE IDs, audiences, billet sets; store then immediately retrieve
    - Assert: retrieved value equals stored value
    - **Validates: Requirements 9.3, 9.10**

  - [ ] 6.3 Write property test for cache expiry enforcement
    - **Property 10: Cache Expiry Enforcement**
    - Store entries with short TTL, use `tokio::time::pause` / advance time past TTL, retrieve
    - Assert: retrieval returns None after TTL
    - **Validates: Requirements 9.5, 9.6**

- [x] 7. Rate limiter
  - [x] 7.1 Implement rate limiter trait and in-memory sliding window implementation
    - Create `src/domain/ratelimit/mod.rs` with `Limiter` trait and `InMemoryLimiter`
    - Implement sliding window or token bucket per SPIFFE ID (configured requests per minute)
    - Return true if allowed, false if rate limited
    - Clean up stale entries periodically
    - _Requirements: 11.1, 11.2_

  - [ ] 7.2 Write property test for rate limiter enforcement
    - **Property 12: Rate Limiter Enforcement**
    - Generate random limits N, send N requests (assert all allowed), send (N+1)th (assert rejected)
    - **Validates: Requirements 11.1**

- [x] 8. Audit logger
  - [x] 8.1 Implement audit logger trait and JSON structured logger
    - Create `src/domain/audit/mod.rs` with `AuditEvent` struct and `AuditLogger` trait
    - Implement JSON logger that serializes events via `tracing` with structured fields
    - Include: spiffe_id, billets, audience, jti, timestamp, success, error
    - _Requirements: 12.1, 12.2, 12.3_

  - [ ] 8.2 Write property test for audit log valid JSON
    - **Property 16: Audit Log Valid JSON**
    - Generate random `AuditEvent` structs (with various Option combinations), serialize
    - Assert: output is valid JSON, contains timestamp, contains available context fields
    - **Validates: Requirements 12.3**

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. SPIRE Server API client and selector enrichment
  - [x] 10.1 Implement SPIRE Server API client trait and implementation
    - Create `src/spireapi/mod.rs` with `RegistrationEntry`, `SpireApiError`, and `SpireApiClient` trait
    - Implement `list_entries_by_spiffe_id` to query SPIRE Server registration API (gRPC or REST)
    - Implement `ping` for health checking
    - Return selectors as Vec<String> (e.g., "k8s:ns:finance", "k8s:sa:payments-sa")
    - _Requirements: 26.1, 26.2_

  - [x] 10.2 Implement selector enricher
    - Create `src/domain/billet/selector.rs` with `SelectorEnricher` trait and implementation
    - Call `SpireApiClient::list_entries_by_spiffe_id`, extract selectors
    - Graceful degradation: return empty Vec and log warning if SPIRE API unreachable or no entry
    - _Requirements: 26.1, 26.2, 26.3, 26.4, 26.5_

  - [ ] 10.3 Write property test for selector enrichment correctness
    - **Property 17: Selector Enrichment Correctness**
    - Generate random SPIFFE IDs and selector sets, mock SPIRE API responses (success, unreachable, no entry)
    - Assert: on success, exact selectors appear in output; on failure, empty set returned
    - **Validates: Requirements 26.1, 26.2, 26.3, 26.4, 26.5**

- [x] 11. Platform-specific entity builder
  - [x] 11.1 Implement entity builder with platform detection and attribute extraction
    - Create `src/domain/billet/entity_builder.rs` with platform detection logic
    - Detect platform from selector prefixes: `k8s:` → K8sWorkload, `aws:` → Ec2Workload, `gcp:` → GcpWorkload, none → Workload
    - Extract platform-specific attributes from selectors (namespace from `k8s:ns:`, service_account from `k8s:sa:`, instance_id from `aws:iid:instance-id:`, etc.)
    - Populate common attributes: spiffe_id, trust_domain, environment, region, selectors
    - _Requirements: 27.1, 27.2, 27.3, 27.4, 27.5, 27.6, 27.7_

  - [ ] 11.2 Write property test for platform-specific entity type selection
    - **Property 18: Platform-Specific Entity Type Selection**
    - Generate random selector sets with various platform prefixes (k8s:, aws:, gcp:, mixed, none)
    - Assert: correct entity type selected and platform-specific attributes populated from corresponding selectors
    - **Validates: Requirements 27.1, 27.2, 27.3, 27.4, 27.5, 27.6**

- [x] 12. Local Cedar authorizer and PolicySyncService
  - [x] 12.1 Implement local Cedar authorizer trait and cedar-policy crate wrapper
    - Create `src/cedar/mod.rs` with `PlatformType`, `WorkloadEntity`, `AuthzDecision`, `BatchAuthzRequest`, `CommonContext`, `AdminAuthzRequest`, `CedarError`, and `LocalAuthorizer` trait
    - Implement `batch_is_authorized`: construct Cedar Request for each billet resource (bare entity IDs from the known billet set) with the ephemeral workload entity as principal and `assumeBillet` as action, evaluate via `cedar_policy::Authorizer::is_authorized()`, return decisions
    - Implement `is_authorized_admin`: construct Cedar Request with billet principals, admin action, target resource, evaluate via `cedar_policy::Authorizer::is_authorized()`
    - Hold `Arc<RwLock<PolicySet>>` provided by PolicySyncService for evaluation
    - No network calls on the evaluation path — all in-process
    - _Requirements: 3.1, 3.2, 3.5, 3.6, 3.7, 18.3, 18.4_

  - [x] 12.2 Implement PolicySyncService
    - Create `src/sync/mod.rs` with `PolicySyncService` and `PolicySyncState`
    - On startup: full scan of quartermaster-policies DynamoDB table via DynamoClient
    - Parse all policy statements into `cedar_policy::PolicySet` using `PolicySet::from_str()`
    - Extract known billet names from policies (parse `Billet::"X"` entity IDs in resource scopes)
    - Atomically swap PolicySet and known billet set (using `Arc<RwLock<Option<PolicySyncState>>>`)
    - Run background poll loop every `policy_sync_interval_secs` (default 30s)
    - On DynamoDB failure during poll: log warning, continue with last successfully loaded PolicySet
    - Report health as degraded only if no PolicySet has ever been loaded (first sync never succeeded)
    - _Requirements: 3.1, 3.4, 13.4_

- [x] 13. DynamoDB client for policy and billet metadata CRUD
  - [x] 13.1 Implement DynamoClient trait and AWS SDK DynamoDB implementation
    - Create `src/dynamo/mod.rs` with `PolicyRecord`, `BilletMetadata`, `DynamoError`, and `DynamoClient` trait
    - Implement using AWS SDK for Rust (DynamoDB client):
      - `list_policies`: Scan quartermaster-policies table, return all PolicyRecord items
      - `create_policy`: PutItem to quartermaster-policies with policy_id, statement, description, created_at, updated_at
      - `update_policy`: UpdateItem on quartermaster-policies (statement, description, updated_at)
      - `delete_policy`: DeleteItem from quartermaster-policies by policy_id
      - `get_billet_metadata`: GetItem from quartermaster-billets by name
      - `put_billet_metadata`: PutItem to quartermaster-billets (name, description, associated_aws_roles, associated_gcp_sas, updated_at)
      - `delete_billet_metadata`: DeleteItem from quartermaster-billets by name
      - `list_billet_metadata`: Scan quartermaster-billets table
      - `ping`: DescribeTable on both tables
    - Map AWS SDK errors to `DynamoError` variants
    - _Requirements: 19.1, 20.1, 21.1, 22.1, 23.1, 24.1, 25.1_

- [ ] 14. Billet resolver
  - [x] 14.1 Implement billet resolver orchestration
    - Create `src/domain/billet/mod.rs` with `Resolution`, `ResolverInput`, `BilletError`, and `Resolver` trait
    - Orchestrate: check cache → if miss, fetch selectors via SelectorEnricher → build ephemeral entity via EntityBuilder → call LocalAuthorizer::batch_is_authorized (resources come from known billet set derived from PolicySet by PolicySyncService) → filter Allow decisions → store in cache → return Resolution
    - Handle cache fallthrough on distributed backend failure
    - Return 403 (Forbidden) when all decisions are Deny
    - Return 503 (ServiceUnavailable) when PolicySet not initialized (first DynamoDB sync not succeeded) and no cache
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 9.4, 9.9_

  - [ ] 14.2 Write property test for billet resolution filter correctness
    - **Property 11: Billet Resolution Filter Correctness**
    - Generate random sets of authorization decisions (mix of Allow/Deny for various billets)
    - Assert: returned billets == exactly those with Allow decision
    - **Validates: Requirements 3.2**

- [x] 15. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Control plane authenticator
  - [x] 16.1 Implement admin authenticator
    - Create `src/domain/admin/authenticator.rs` with `AdminAuthError` and `Authenticator` trait
    - Parse Bearer token from Authorization header
    - Verify JWT signature against Quartermaster's own JWKS (using SigningManager)
    - Check JWT expiry
    - Extract billets from JWT claims
    - Call LocalAuthorizer::is_authorized_admin with billets as principals, action, resource
    - Return authenticated SPIFFE ID or typed error (401 missing/invalid token, 403 insufficient privileges)
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.8_

  - [ ] 16.2 Write property test for admin authentication correctness
    - **Property 14: Admin Authentication Correctness**
    - Generate tokens with various billet combinations, mock local Cedar authorizer responses, test valid/invalid signatures, expired tokens
    - Assert: succeeds iff (valid sig AND not expired AND Cedar returns Allow for at least one billet)
    - **Validates: Requirements 18.2, 18.3, 18.4**

- [x] 17. Admin billet and policy CRUD services
  - [x] 17.1 Implement billet CRUD service
    - Create `src/domain/admin/billets.rs` with billet management logic
    - Create: validate name non-empty, check uniqueness via DynamoClient, create record in quartermaster-billets DynamoDB table, return 201
    - List: retrieve all billet metadata from DynamoDB (enriched with known billet names from PolicySyncService), return 200 with JSON array
    - Get: retrieve single billet metadata by name from DynamoDB, return 200 or 404
    - Delete: check not `quartermaster-admin`, delete from DynamoDB, return 204 or 404
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 20.1, 20.2, 20.3, 21.1, 21.2, 21.3, 22.1, 22.2, 22.3, 22.4_

  - [x] 17.2 Implement policy CRUD service
    - Create `src/domain/admin/policies.rs` with policy management logic
    - Create: validate Cedar statement syntax locally (parse with cedar_policy::PolicySet::from_str, validate against Cedar schema), generate UUID for policy_id, write to quartermaster-policies DynamoDB table, return 201 with id
    - Update: validate statement locally, update in DynamoDB, return 200 or 404
    - Delete: delete from DynamoDB, return 204 or 404
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 24.1, 24.2, 24.3, 24.4, 24.5, 25.1, 25.2, 25.3_

- [x] 18. OIDC discovery document builder
  - [x] 18.1 Implement OIDC discovery document construction
    - Create `src/oidc/mod.rs` with `DiscoveryDocument` struct
    - Build document from config: issuer, jwks_uri (issuer + "/jwks.json"), response_types_supported: ["id_token"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: [configured alg], claims_supported: ["sub", "iss", "aud", "exp", "iat", "billets", "jti"]
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ] 18.2 Write property test for OIDC discovery construction
    - **Property 13: OIDC Discovery Construction**
    - Generate random issuer URLs and algorithm values
    - Assert: document contains all required fields with correct values
    - **Validates: Requirements 6.2, 6.3, 6.4, 6.5, 6.6, 6.7**

- [x] 19. HTTP server and handlers
  - [x] 19.1 Implement HTTP server setup with axum router and middleware
    - Create `src/server/mod.rs` with axum Router setup, route registration
    - Create `src/server/middleware.rs` with tower layers: request ID, tracing, panic recovery
    - Wire shared application state (Arc holding all domain components)
    - _Requirements: 2.1, 13.1_

  - [x] 19.2 Implement token exchange handler (POST /token)
    - Create `src/handler/token.rs` with form parsing, request validation
    - Parse `application/x-www-form-urlencoded` body: grant_type, subject_token, subject_token_type, audience, csr (optional)
    - Validate required params and expected values, return 400 on mismatch
    - Orchestrate: rate limit → validate SVID → resolve billets → issue JWT → (optional) issue cert → audit log → return response
    - Decode CSR from base64 if present
    - Build `TokenExchangeResponse` JSON (access_token, issued_token_type, token_type, expires_in, certificate_chain if CSR was provided)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 4.8, 5.10, 5.11, 14.1, 14.2, 14.3, 14.4, 14.5_

  - [x] 19.3 Implement OIDC and JWKS handlers
    - Create `src/handler/oidc.rs` for GET `/.well-known/openid-configuration` returning discovery JSON
    - Create `src/handler/jwks.rs` for GET `/jwks.json` returning JWKS from SigningManager
    - _Requirements: 6.1, 7.1_

  - [x] 19.4 Implement CA trust bundle handler
    - Create `src/handler/ca.rs` for GET `/ca/chain.pem`
    - Return PEM-encoded CA certificate chain with Content-Type `application/x-pem-file`
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 19.5 Implement health check handler
    - Create `src/handler/health.rs` for GET `/healthz`
    - Check: SPIRE trust bundle loaded AND PolicySet has been loaded at least once (first DynamoDB sync succeeded)
    - Return 200 if healthy, 503 if either dependency not ready
    - Does NOT check DynamoDB reachability on every health check (sync loop handles connectivity)
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [x] 19.6 Implement admin billet handlers
    - Create `src/handler/admin_billets.rs` with POST/GET/GET{name}/DELETE /admin/billets handlers
    - Each handler: authenticate via Authenticator (extracting Bearer token, evaluating appropriate admin action), then delegate to billet CRUD service
    - Return appropriate status codes and JSON responses
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 20.1, 20.2, 20.3, 21.1, 21.2, 21.3, 22.1, 22.2, 22.3, 22.4_

  - [x] 19.7 Implement admin policy handlers
    - Create `src/handler/admin_policies.rs` with POST/PUT{id}/DELETE{id} /admin/policies handlers
    - Each handler: authenticate, then delegate to policy CRUD service
    - Return appropriate status codes and JSON responses
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 24.1, 24.2, 24.3, 24.4, 24.5, 25.1, 25.2, 25.3_

  - [x] 19.8 Implement billet metadata handler (GET /billets/{name})
    - Create `src/handler/billets.rs` for data-plane billet metadata
    - Require valid Quartermaster JWT, evaluate `readBillet` authorization via local Cedar evaluator
    - Retrieve billet metadata from DynamoDB (quartermaster-billets table)
    - Return billet metadata (name, description, associated_aws_roles, associated_gcp_sas) if authorized
    - Return 403 if unauthorized, 404 if billet not found
    - _Requirements: 28.1, 28.2, 28.3, 28.4, 28.5, 28.6, 28.7, 28.8_

- [x] 20. Cross-credential consistency and integration wiring
  - [x] 20.1 Implement main.rs entrypoint with dependency injection
    - Create `src/main.rs`: load config, initialize all components, wire dependencies, start axum server
    - Construct: SigningManager → Validator, Issuer, Authority, Cache, RateLimiter, AuditLogger, SelectorEnricher, EntityBuilder, DynamoClient, PolicySyncService, LocalAuthorizer, BilletResolver, Authenticator
    - Start PolicySyncService background sync loop (initial scan + periodic refresh)
    - Wait for first successful PolicySet load before accepting traffic (or report 503)
    - _Requirements: All (integration)_

  - [ ] 20.2 Write property test for cross-credential consistency
    - **Property 8: Cross-Credential Consistency**
    - Generate random SPIFFE IDs, audiences, billet sets; perform full exchange producing both JWT and cert
    - Assert: SPIFFE ID in cert URI SAN == sub claim in JWT, billets in cert qm-billet:// SANs == billets claim in JWT
    - **Validates: Requirements 17.2, 17.3**

- [x] 21. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 22. Integration tests
  - [ ] 22.1 Write integration tests for token exchange flow
    - Test full POST /token flow with mock SVID, mock SPIRE API, mock Cedar authorizer
    - Verify JWT issuance, certificate issuance (with CSR), response format, cache behavior
    - Test error paths: invalid SVID (401), no billets (403), rate limited (429), service unavailable (503)
    - _Requirements: 2.1-2.8, 4.8, 5.10, 5.11, 14.1-14.5_

  - [ ] 22.2 Write integration tests for OIDC + JWKS + token verification
    - Start test server, fetch discovery doc, fetch JWKS, issue a token, verify token signature using JWKS keys
    - Assert: issuer in discovery matches iss in token, kid matches, signature valid
    - _Requirements: 6.1-6.7, 7.1-7.4, 16.1-16.3_

  - [ ] 22.3 Write integration tests for admin CRUD operations
    - Test billet create/list/get/delete and policy create/update/delete through HTTP handlers
    - Mock DynamoClient, verify admin authentication and authorization flow
    - Verify local Cedar syntax validation on policy create/update (reject invalid Cedar before DynamoDB write)
    - Test error cases: unauthorized (401), forbidden (403), not found (404), conflict (409)
    - _Requirements: 18.1-18.10, 19.1-19.7, 20.1-20.3, 21.1-21.3, 22.1-22.4, 23.1-23.6, 24.1-24.5, 25.1-25.3_

  - [ ] 22.4 Write integration tests for certificate chain verification
    - Issue certificate via token exchange, fetch CA chain from /ca/chain.pem, verify cert chain
    - _Requirements: 8.1-8.3, 17.1_

- [x] 23. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using `proptest` with minimum 100 iterations
- Unit tests validate specific examples and edge cases
- All external dependencies (DynamoDB, SPIRE) are accessed through traits enabling test doubles
- The implementation uses Rust with axum, jsonwebtoken, rcgen, ring, cedar-policy, and aws-sdk-dynamodb
- No AVP dependency: cedar-policy crate provides local Cedar evaluation; DynamoDB is the single backing store
