# Implementation Plan: OpenAPI Spec Generation via `utoipa`

## Overview

Add compile-time OpenAPI 3.1 documentation generation to Quartermaster using `utoipa` v5 and `utoipa-axum`. Annotate all 17 endpoints and their request/response types, aggregate into a centralized `ApiDoc` struct, and serve the generated spec at `GET /openapi.json`. Includes renaming the admin `BilletMetadataResponse` to `AdminBilletMetadataResponse` to avoid schema name collision.

## Tasks

- [x] 1. Add dependencies and create the openapi module
  - [x] 1.1 Add `utoipa` and `utoipa-axum` to `Cargo.toml`
    - Add `utoipa = { version = "5", features = ["axum_extras"] }` to `[dependencies]`
    - Add `utoipa-axum = "0.2"` to `[dependencies]`
    - _Requirements: 1.1_

  - [x] 1.2 Create `src/openapi.rs` with `ApiDoc` struct and `openapi_json` handler
    - Define the `ApiDoc` struct with `#[derive(OpenApi)]`
    - Include `info(title, version, description)`, `paths(...)`, `components(schemas = [...])`, `modifiers(&SecurityAddon)`, and `tags(...)`
    - Implement the `SecurityAddon` modifier adding `BearerAuth` and `MutualTLS` security schemes
    - Implement the `openapi_json` async handler that serializes the spec to JSON
    - _Requirements: 1.4, 2.1, 2.3, 2.4_

  - [x] 1.3 Register `pub mod openapi;` in `src/lib.rs`
    - _Requirements: 1.4_

  - [x] 1.4 Register `GET /openapi.json` route in `src/server/mod.rs`
    - Add the route to `build_main_router` (outside admin-gated block)
    - No authentication middleware on this route
    - _Requirements: 2.1, 2.2, 2.5_

- [x] 2. Rename admin `BilletMetadataResponse` and annotate admin handler types
  - [x] 2.1 Rename `BilletMetadataResponse` to `AdminBilletMetadataResponse` in `src/handler/admin_billets.rs`
    - Rename the struct definition
    - Update all usages within the file (create_billet, update_billet return values)
    - _Requirements: 4.1, 4.2_

  - [x] 2.2 Add `#[derive(utoipa::ToSchema)]` to all request/response types in `src/handler/admin_billets.rs`
    - Annotate: `CreateBilletRequest`, `UpdateBilletRequest`, `CreatePolicyRequest`, `UpdatePolicyRequest`, `PolicyResponse`, `AdminBilletMetadataResponse`
    - Ensure optional fields in `UpdateBilletRequest` are correctly represented
    - _Requirements: 4.1, 4.2, 4.3_

  - [x] 2.3 Add `#[utoipa::path]` annotations to all admin billet handlers
    - Annotate: `create_billet`, `list_billets`, `get_billet`, `update_billet`, `delete_billet`
    - Include method, path, tags (`admin-billets`), request body schemas, response codes (201/200/204, 401, 403, 404), and security requirements (`BearerAuth`)
    - _Requirements: 1.2, 3.1, 3.2, 3.3_

  - [x] 2.4 Add `#[utoipa::path]` annotations to all admin policy handlers
    - Annotate: `create_policy`, `list_policies`, `get_policy`, `update_policy`, `delete_policy`
    - Include method, path, tags (`admin-policies`), request body schemas, response codes, and security requirements (`BearerAuth`)
    - _Requirements: 1.2, 3.1, 3.2, 3.3_

- [x] 3. Annotate data-plane handler types and endpoints
  - [x] 3.1 Annotate `src/handler/token.rs`
    - Add `#[derive(utoipa::ToSchema)]` to `TokenExchangeForm` and `TokenExchangeResponse`
    - Add `#[utoipa::path]` to `token_exchange` with tag `token-exchange`, content-type `application/x-www-form-urlencoded`, security `MutualTLS`, response codes (200, 400, 401)
    - _Requirements: 1.2, 1.3, 3.1, 3.4, 4.1, 4.2, 4.3_

  - [x] 3.2 Annotate `src/handler/billets_discovery.rs`
    - Add `#[derive(utoipa::ToSchema)]` to `BilletDiscoveryForm` and `BilletDiscoveryResponse`
    - Add `#[utoipa::path]` to `billet_discovery` with tag `discovery`, content-type `application/x-www-form-urlencoded`, security `MutualTLS`, response codes (200, 400, 401)
    - _Requirements: 1.2, 1.3, 3.1, 3.4, 4.1, 4.2_

  - [x] 3.3 Annotate `src/handler/billets.rs`
    - Add `#[derive(utoipa::ToSchema)]` to `BilletMetadataResponse`
    - Add `#[utoipa::path]` to `get_billet` with tag `discovery`, security `BearerAuth`, response codes (200, 401, 403, 404)
    - _Requirements: 1.2, 1.3, 3.1, 3.2, 3.3, 4.2_

  - [x] 3.4 Annotate `src/handler/health.rs`
    - Add `#[derive(utoipa::ToSchema)]` to `HealthResponse`
    - Add `#[utoipa::path]` to `healthz` with tag `system`, response codes (200)
    - _Requirements: 1.2, 1.3, 3.1, 3.3, 4.2_

  - [x] 3.5 Annotate `src/handler/oidc.rs`
    - Add `#[utoipa::path]` to `openid_configuration` with tag `discovery`, response codes (200)
    - _Requirements: 1.2, 3.1, 3.3_

  - [x] 3.6 Annotate `src/handler/jwks.rs`
    - Add `#[utoipa::path]` to `jwks` with tag `discovery`, response codes (200)
    - _Requirements: 1.2, 3.1, 3.3_

  - [x] 3.7 Annotate `src/handler/ca.rs`
    - Add `#[utoipa::path]` to `ca_chain` with tag `discovery`, response codes (200)
    - _Requirements: 1.2, 3.1, 3.3_

- [x] 4. Annotate shared types in domain and oidc modules
  - [x] 4.1 Add `#[derive(utoipa::ToSchema)]` to `ErrorBody` in `src/domain/mod.rs`
    - Use `#[schema(as = ErrorResponse)]` to expose as `ErrorResponse` in the OpenAPI schema
    - _Requirements: 4.2_

  - [x] 4.2 Add `#[derive(utoipa::ToSchema)]` to `DiscoveryDocument` in `src/oidc/mod.rs`
    - _Requirements: 4.2_

  - [x] 4.3 Add `#[derive(utoipa::ToSchema)]` to `BilletWithPolicies` in the admin billets domain
    - Ensure the struct used by `get_billet` admin handler derives `ToSchema`
    - _Requirements: 4.2_

- [x] 5. Checkpoint — Ensure compilation succeeds
  - Run `cargo check` to verify all annotations compile correctly
  - Ensure all types referenced in `ApiDoc` paths and schemas are correctly wired
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Write property-based tests for OpenAPI spec correctness
  - [ ]* 6.1 Write property test: All endpoints documented with correct HTTP methods
    - **Property 1: All endpoints documented with correct HTTP methods**
    - For each (method, path) in the 17-endpoint set, verify the generated OpenAPI JSON contains the path with the correct HTTP method operation
    - **Validates: Requirements 1.2, 3.1**

  - [ ]* 6.2 Write property test: All expected types present in schemas
    - **Property 2: All expected types present in schemas**
    - For each type name in the expected set (15 types), verify `components.schemas` contains a definition with that name
    - **Validates: Requirements 1.3, 4.1, 4.2**

  - [ ]* 6.3 Write property test: Spec structural completeness
    - **Property 3: Spec structural completeness**
    - Verify the generated doc contains: non-empty `info` with title/version, non-empty `paths`, `components.schemas` with ≥10 entries, `components.securitySchemes` with both `BearerAuth` and `MutualTLS`
    - **Validates: Requirements 2.3, 2.4**

  - [ ]* 6.4 Write property test: Endpoints tagged correctly
    - **Property 4: Endpoints tagged correctly**
    - For each path operation, verify the `tags` array contains the prescribed tag per the tag-to-endpoint mapping
    - **Validates: Requirements 3.3**

  - [ ]* 6.5 Write property test: Each endpoint documents response codes
    - **Property 5: Each endpoint documents response codes**
    - For each path operation, verify at least one success code (200/201/204) and, for authenticated endpoints, at least one error code (401/403)
    - **Validates: Requirements 3.2**

  - [ ]* 6.6 Write property test: Optional fields not marked required
    - **Property 6: Optional fields not marked required**
    - For schemas with `Option<T>` fields (TokenExchangeForm, UpdateBilletRequest, TokenExchangeResponse), verify optional field names do not appear in the `required` array
    - **Validates: Requirements 4.3**

  - [ ]* 6.7 Write property test: No vendor extensions
    - **Property 7: No vendor extensions**
    - Verify no key at any depth in the generated OpenAPI JSON starts with `x-`
    - **Validates: Requirements 5.2**

- [x] 7. Final checkpoint — Ensure all tests pass
  - Run `cargo test` to verify all property tests and existing tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The admin `BilletMetadataResponse` rename (task 2.1) must happen before annotating that file to avoid schema name collisions
- Property tests use `proptest` (already in dev-dependencies) and validate correctness properties from the design document
- The `/openapi.json` endpoint is excluded from the OpenAPI `paths` list (it is meta-documentation)
- All annotation errors are compile-time — the spec cannot be accidentally incomplete
