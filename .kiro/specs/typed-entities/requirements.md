# Requirements Document — Wire Typed Cedar Entities into Billet Resolution

## Introduction

All typed Cedar entity construction code exists (`build_cedar_entity`, `HumanIdentity`, `AwsRoleIdentity`, `GcpIdentity`) but is never called from the billet resolver or handlers. Currently all identity sources are squeezed into a generic `Workload` entity with no useful attributes for non-SPIRE sources. This spec wires the existing entity builders into the live resolution path and cleans up the OIDC claims model.

## Existing Implementation Status

- **`MultiSourceEntityBuilder`** — EXISTS. Converts `AuthenticatedIdentity` variants into intermediate `CedarPrincipal` types.
- **`build_cedar_entity()`** — EXISTS. Converts `CedarPrincipal` into Cedar `Entity` objects with typed attributes.
- **`principal_entity_uid()`** — EXISTS. Returns the Cedar `EntityUid` for any principal.
- **`build_identity_context()`** — EXISTS. Builds Cedar context with `source_type`, `source_cloud`, etc.
- **`BilletResolverImpl`** — uses `build_workload_entities_from_captures` for ALL sources. Non-SPIRE sources get an empty captures map → generic Workload entity with no attributes.

## Requirements

### Requirement 1: Resolver Uses Typed Entity Builders for Non-SPIRE Sources

#### Acceptance Criteria

1. THE billet resolver (or handler calling it) SHALL branch on `AuthenticatedIdentity` variant:
   - `Spire` → `PathPatternMatcher::extract` + `build_workload_entities_from_captures` (unchanged)
   - `Oidc` → `build_cedar_entity(CedarPrincipal::Human(...))` using existing code
   - `AwsSts` → `build_cedar_entity(CedarPrincipal::AwsRole(...))` using existing code
   - `Gcp` → `build_cedar_entity(CedarPrincipal::GcpWorkload(...))` using existing code
2. The resulting Cedar `Entity` + `EntityUid` SHALL be passed to the Cedar authorizer for `assumeBillet` evaluation
3. The Cedar `Context` SHALL be built via existing `build_identity_context()` which already includes `source_type`

### Requirement 2: Rename Cedar Entity Type `HumanIdentity` → `OidcIdentity`

#### Acceptance Criteria

1. THE Cedar entity type SHALL be `Quartermaster::OidcIdentity` (not `HumanIdentity`) since OIDC tokens can represent service identities
2. Rename in: `principal_entity_uid()`, `build_human_cedar_entity()`, the `CedarPrincipal` enum variant name (`Human` → `Oidc`)
3. THE struct `HumanEntity` SHALL be renamed to `OidcEntity`
4. Add a `subject_type` attribute on the entity (String: `"human"` or `"service"`) — default `"human"`, overridable per IdP config in the future

### Requirement 3: Fix OIDC Claims Flattening

#### Acceptance Criteria

1. THE current behavior (flatten all claims into a single `groups` set) loses which claim a value came from. THE entity SHALL expose claims in a way that preserves claim origin.
2. THE `OidcIdentity` Cedar entity SHALL have:
   - `email` (String)
   - `idp_prefix` (String)
   - `subject` (String)
   - `subject_type` (String) — `"human"` or `"service"`
   - `groups` (Set of String) — flattened union of all claim values (for backward compat / simple matching)
   - `claims` (Set of String) — all values in `claim_name:value` format for origin-preserving matching
3. This enables both styles of policy:
   ```cedar
   // Simple: just check if they're in billing-ops (any claim)
   when { principal.groups.contains("billing-ops") };

   // Precise: check it came from the "roles" claim specifically
   when { principal.claims.contains("roles:billing-ops") };
   ```

### Requirement 4: Remove Dead SPIRE Entity Code

#### Acceptance Criteria

1. Remove `PlatformType` enum from `cedar/mod.rs`
2. Remove `WorkloadEntity` struct from `cedar/mod.rs`
3. Remove `entity_builder.rs` file entirely
4. Remove `CedarPrincipal::Workload` variant and the SPIRE arm in `build_principal`
5. Remove `spire_builder` field from `MultiSourceEntityBuilder`
6. Remove the `selectors` parameter from `build_principal` (no longer needed)
7. Remove `AppState.entity_builder` if fully unused after wiring

### Requirement 5: Cedar Schema Update

#### Acceptance Criteria

1. THE `assumeBillet` action's `principalTypes` SHALL include: `Workload`, `OidcIdentity`, `AwsRoleIdentity`, `GcpIdentity`
2. All admin actions SHALL also accept these types as principals
3. `OidcIdentity` schema SHALL declare: `email: String`, `idp_prefix: String`, `subject: String`, `subject_type: String`, `groups: Set<String>`, `claims: Set<String>`
4. `AwsRoleIdentity` schema SHALL declare: `account_id: String`, `role_arn: String`, `role_name: String`, `role_path: String`
5. `GcpIdentity` schema SHALL declare: `project_id: String`, `email: String`, `zone: String`
