# Design Document — OpenAPI Spec Generation via `utoipa`

## Overview

This design adds compile-time OpenAPI 3.1 documentation generation to Quartermaster using the `utoipa` crate ecosystem. The approach is code-first: annotations on handler functions and request/response types produce the OpenAPI specification at compile time, ensuring documentation never drifts from implementation.

The generated spec is served at runtime via `GET /openapi.json` (unauthenticated) and can be used for client library generation, developer portals, and CI-based offline spec export.

### Key Design Decisions

1. **utoipa v5 + utoipa-axum**: Latest stable release targeting OpenAPI 3.1.0 with native axum integration.
2. **Compile-time generation**: The spec is derived from macro annotations, not runtime reflection. No performance cost at request time beyond JSON serialization.
3. **Centralized `ApiDoc` struct**: A single `#[derive(OpenApi)]` struct in `src/openapi.rs` aggregates all paths and schemas, making it easy to audit completeness.
4. **Separate handler for serving**: A dedicated `GET /openapi.json` handler returns the serialized spec. This handler is registered on the router but intentionally excluded from the `ApiDoc` paths list.
5. **No UI crate**: The requirements only call for raw JSON at `/openapi.json`. No Swagger UI or Scalar is included (can be added later).

## Architecture

```mermaid
graph TD
    subgraph Compile Time
        A[Handler annotations<br/>#[utoipa::path]] --> D[ApiDoc struct<br/>#[derive(OpenApi)]]
        B[Type annotations<br/>#[derive(ToSchema)]] --> D
        C[Security schemes<br/>modifiers] --> D
    end

    subgraph Runtime
        D --> E[ApiDoc::openapi()]
        E --> F[utoipa::openapi::OpenApi]
        F --> G[GET /openapi.json handler]
        G --> H[JSON response]
    end

    subgraph Router
        I[build_main_router] --> J[/openapi.json route]
        J --> G
    end
```

The architecture is straightforward:

1. **Annotation layer** — Each handler gets `#[utoipa::path(...)]` specifying method, path, tags, request/response schemas, and security requirements. Each struct used in requests/responses derives `ToSchema`.
2. **Aggregation layer** — `ApiDoc` in `src/openapi.rs` uses `#[derive(OpenApi)]` with `paths(...)` and `components(schemas = [...])` to pull everything together. A `Modify` implementation adds security scheme definitions.
3. **Serving layer** — A handler calls `ApiDoc::openapi().to_pretty_json()` and returns it with `Content-Type: application/json`.

## Components and Interfaces

### New Files

| File | Purpose |
|------|---------|
| `src/openapi.rs` | `ApiDoc` struct, security scheme modifier, `/openapi.json` handler |

### Modified Files

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `utoipa` and `utoipa-axum` dependencies |
| `src/lib.rs` | Add `pub mod openapi;` |
| `src/server/mod.rs` | Register `GET /openapi.json` route |
| `src/handler/token.rs` | Add `#[utoipa::path]` to `token_exchange`, `#[derive(ToSchema)]` to `TokenExchangeForm` and `TokenExchangeResponse` |
| `src/handler/billets_discovery.rs` | Add `#[utoipa::path]` to `billet_discovery`, `#[derive(ToSchema)]` to `BilletDiscoveryForm` and `BilletDiscoveryResponse` |
| `src/handler/billets.rs` | Add `#[utoipa::path]` to `get_billet`, `#[derive(ToSchema)]` to `BilletMetadataResponse` |
| `src/handler/admin_billets.rs` | Add `#[utoipa::path]` to all admin handlers, `#[derive(ToSchema)]` to all request/response types, rename `BilletMetadataResponse` → `AdminBilletMetadataResponse` |
| `src/handler/health.rs` | Add `#[utoipa::path]` to `healthz`, `#[derive(ToSchema)]` to `HealthResponse` |
| `src/handler/oidc.rs` | Add `#[utoipa::path]` to `openid_configuration` |
| `src/handler/jwks.rs` | Add `#[utoipa::path]` to `jwks` |
| `src/handler/ca.rs` | Add `#[utoipa::path]` to `ca_chain` |
| `src/oidc/mod.rs` | Add `#[derive(ToSchema)]` to `DiscoveryDocument` |
| `src/domain/mod.rs` | Add `#[derive(ToSchema)]` to `ErrorBody` (expose as `ErrorResponse` schema) |

### Interfaces

**`src/openapi.rs` public API:**

```rust
use utoipa::OpenApi;

/// Aggregates all OpenAPI paths, schemas, and security schemes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Quartermaster",
        version = "0.1.0",
        description = "Workload identity federation broker"
    ),
    paths(
        handler::token::token_exchange,
        handler::billets_discovery::billet_discovery,
        handler::billets::get_billet,
        handler::oidc::openid_configuration,
        handler::jwks::jwks,
        handler::ca::ca_chain,
        handler::health::healthz,
        handler::admin_billets::create_billet,
        handler::admin_billets::list_billets,
        handler::admin_billets::get_billet,
        handler::admin_billets::update_billet,
        handler::admin_billets::delete_billet,
        handler::admin_billets::create_policy,
        handler::admin_billets::list_policies,
        handler::admin_billets::get_policy,
        handler::admin_billets::update_policy,
        handler::admin_billets::delete_policy,
    ),
    components(
        schemas(
            TokenExchangeForm, TokenExchangeResponse,
            BilletDiscoveryForm, BilletDiscoveryResponse,
            BilletMetadataResponse, AdminBilletMetadataResponse,
            BilletWithPolicies,
            CreateBilletRequest, UpdateBilletRequest,
            CreatePolicyRequest, UpdatePolicyRequest,
            PolicyResponse, ErrorResponse,
            HealthResponse, DiscoveryDocument,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "token-exchange", description = "RFC 8693 token exchange"),
        (name = "discovery", description = "OIDC discovery, JWKS, CA chain, billet lookup"),
        (name = "admin-billets", description = "Billet CRUD (admin control plane)"),
        (name = "admin-policies", description = "Policy CRUD (admin control plane)"),
        (name = "system", description = "Health and operational endpoints"),
    )
)]
pub struct ApiDoc;

/// Adds BearerAuth and MutualTLS security schemes.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // Add security schemes to components
    }
}

/// GET /openapi.json — returns the generated OpenAPI spec.
pub async fn openapi_json() -> impl IntoResponse { ... }
```

### Tag-to-Endpoint Mapping

| Tag | Endpoints |
|-----|-----------|
| `token-exchange` | `POST /token` |
| `discovery` | `POST /billets/me`, `GET /.well-known/openid-configuration`, `GET /jwks.json`, `GET /ca/chain.pem`, `GET /billets/{name}` |
| `admin-billets` | `POST /admin/billets`, `GET /admin/billets`, `GET /admin/billets/{name}`, `PUT /admin/billets/{name}`, `DELETE /admin/billets/{name}` |
| `admin-policies` | `POST /admin/billets/{name}/policies`, `GET /admin/billets/{name}/policies`, `GET /admin/billets/{name}/policies/{id}`, `PUT /admin/billets/{name}/policies/{id}`, `DELETE /admin/billets/{name}/policies/{id}` |
| `system` | `GET /healthz` |

### Security Scheme Mapping

| Scheme | Endpoints |
|--------|-----------|
| `BearerAuth` | All `/admin/*` endpoints, `GET /billets/{name}` |
| `MutualTLS` | `POST /token`, `POST /billets/me` (when subject_token is omitted) |

## Data Models

### Security Schemes (in generated OpenAPI)

```json
{
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      },
      "MutualTLS": {
        "type": "mutualTLS"
      }
    }
  }
}
```

### Types Requiring `ToSchema`

**Request types:**
- `TokenExchangeForm` — fields: grant_type?, subject_token?, subject_token_type?, audience?, csr?, billets?
- `BilletDiscoveryForm` — fields: subject_token?, subject_token_type?
- `CreateBilletRequest` — fields: name, description, associated_aws_roles[], associated_gcp_sas[], tags[]
- `UpdateBilletRequest` — fields: description?, associated_aws_roles?, associated_gcp_sas?, tags?
- `CreatePolicyRequest` — fields: statement, description
- `UpdatePolicyRequest` — fields: statement, description

**Response types:**
- `TokenExchangeResponse` — fields: access_token, issued_token_type, token_type, expires_in, certificate_chain?
- `BilletDiscoveryResponse` — fields: billets[], implicit_billets[], cedar_billets[]
- `BilletMetadataResponse` (handler::billets) — fields: name, description, associated_aws_roles[], associated_gcp_sas[]
- `AdminBilletMetadataResponse` (handler::admin_billets, renamed from `BilletMetadataResponse`) — fields: name, description, associated_aws_roles[], associated_gcp_sas[], tags[], updated_at
- `BilletWithPolicies` — fields: name, description, associated_aws_roles[], associated_gcp_sas[], tags[], updated_at, policies[]
- `PolicyResponse` — fields: id, statement, description
- `ErrorResponse` — fields: error, error_description
- `HealthResponse` — fields: status, checks{datastore, signing_key, policy_sync}
- `DiscoveryDocument` — fields: issuer, jwks_uri, response_types_supported[], subject_types_supported[], id_token_signing_alg_values_supported[], claims_supported[]

### Dependency Additions

```toml
[dependencies]
utoipa = { version = "5", features = ["axum_extras"] }
utoipa-axum = "0.2"
```

The `axum_extras` feature enables recognition of axum extractors like `Form`, `Path`, `Query`, and `Json` for automatic parameter/body inference.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: All endpoints documented with correct HTTP methods

*For any* (method, path) tuple in the defined set of 17 endpoints, the generated OpenAPI JSON `paths` object SHALL contain an entry for that path with an operation matching the expected HTTP method.

**Validates: Requirements 1.2, 3.1**

### Property 2: All expected types present in schemas

*For any* type name in the defined set of request and response types (TokenExchangeForm, TokenExchangeResponse, BilletDiscoveryForm, BilletDiscoveryResponse, BilletMetadataResponse, AdminBilletMetadataResponse, CreateBilletRequest, UpdateBilletRequest, CreatePolicyRequest, UpdatePolicyRequest, PolicyResponse, ErrorResponse, HealthResponse, DiscoveryDocument, BilletWithPolicies), the generated OpenAPI JSON `components.schemas` object SHALL contain a schema definition with that name.

**Validates: Requirements 1.3, 4.1, 4.2**

### Property 3: Spec structural completeness

*For any* generated OpenAPI document from `ApiDoc::openapi()`, the JSON SHALL contain: a non-empty `info` object with `title` and `version`, a non-empty `paths` object, a `components.schemas` object with at least 10 entries, and a `components.securitySchemes` object containing both `BearerAuth` and `MutualTLS`.

**Validates: Requirements 2.3, 2.4**

### Property 4: Endpoints tagged correctly

*For any* path operation in the generated OpenAPI document, the `tags` array SHALL contain exactly the tag prescribed by the tag-to-endpoint mapping (token-exchange, discovery, admin-billets, admin-policies, or system).

**Validates: Requirements 3.3**

### Property 5: Each endpoint documents response codes

*For any* path operation in the generated OpenAPI document, the `responses` object SHALL contain at least one success response code (200, 201, or 204) and, for authenticated endpoints, at least one error response code (401 or 403).

**Validates: Requirements 3.2**

### Property 6: Optional fields not marked required

*For any* schema in the generated OpenAPI document that corresponds to a Rust struct with `Option<T>` fields (TokenExchangeForm, UpdateBilletRequest, TokenExchangeResponse), the optional field names SHALL NOT appear in the schema's `required` array.

**Validates: Requirements 4.3**

### Property 7: No vendor extensions

*For any* key at any depth in the generated OpenAPI JSON document tree, no key SHALL start with the prefix `x-`.

**Validates: Requirements 5.2**

## Error Handling

### `/openapi.json` Endpoint

The handler is infallible by design — `ApiDoc::openapi()` is a compile-time-generated function that always succeeds. The only possible failure is JSON serialization, which is handled by returning a 500 with an error body:

```rust
pub async fn openapi_json() -> impl IntoResponse {
    let spec = ApiDoc::openapi();
    match spec.to_pretty_json() {
        Ok(json) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json,
        ).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
```

In practice, serialization will never fail because the spec is statically constructed from valid types.

### Annotation Errors

All annotation errors are compile-time errors. If a `#[utoipa::path]` references a type that doesn't derive `ToSchema`, or if parameter names don't match, the project will fail to compile. This is a feature — the spec cannot be accidentally incomplete.

## Testing Strategy

### Unit Tests (example-based)

| Test | What it verifies |
|------|-----------------|
| `GET /openapi.json` returns 200 | Route registered, handler works |
| No auth required for `/openapi.json` | Public access without Authorization header |
| `/openapi.json` not in documented paths | Meta-endpoint excluded from spec |
| `POST /token` uses `application/x-www-form-urlencoded` content type | Form encoding documented correctly |
| `POST /billets/me` uses `application/x-www-form-urlencoded` content type | Form encoding documented correctly |
| Security schemes include BearerAuth (http/bearer) and MutualTLS | Correct scheme types |

### Property-Based Tests

Property-based testing is appropriate here because the generated OpenAPI spec has universal structural invariants that should hold regardless of how the code evolves. The properties verify completeness and correctness guarantees across all endpoints and types.

**Library**: `proptest` (already in dev-dependencies)

**Configuration**: Minimum 100 iterations per property test.

**Tag format**: `Feature: openapi, Property {N}: {property_text}`

Each correctness property (1–7) maps to a single property-based test that generates test cases from the defined endpoint/type sets and verifies the invariant holds for each member.

### Integration Tests

| Test | What it verifies |
|------|-----------------|
| Generated spec validates against OpenAPI 3.1 JSON schema | Spec is valid for codegen tools |
| `openapi-generator-cli validate` passes | End-to-end codegen compatibility |

### CI Pipeline Addition

A CI step should:
1. Start the server (or extract the spec at build time)
2. Fetch `GET /openapi.json`
3. Convert to YAML and commit to `docs/openapi.yaml`
4. Validate with `openapi-generator-cli validate`
