# Requirements Document — Multi-Source Identity & Unified Billet Resolution

## Introduction

This spec extends Quartermaster to accept multiple upstream identity sources (SPIRE SVIDs, corporate OIDC tokens, AWS presigned STS, GCP identity tokens) and evaluate all of them through the same Cedar policy engine for billet resolution. Each identity source produces a typed principal entity with source-specific attributes in context — Cedar policies can condition on any of these attributes uniformly.

Additionally, each configured IdP source may optionally enable **implicit billet mapping**, where group claims from the IdP are mechanically mapped to prefixed billets without Cedar evaluation. This is a convenience shortcut — operators can use it for fast onboarding and progressively move to Cedar-evaluated billets as their policy model matures.

## Glossary

- **Identity_Source**: A configured upstream token type that Quartermaster can validate (SPIRE, OIDC IdP, AWS presigned STS, GCP identity token)
- **IdP_Source**: A specific OIDC identity provider configuration with: prefix, issuer URL, allowed client IDs, group claim name, and implicit mapping toggle
- **Implicit_Billet_Mapping**: An optional per-IdP feature where group claims are automatically mapped to prefixed billets (e.g., Okta group `billing-ops` → billet `okta:billing-ops`) without Cedar evaluation
- **Cedar_Evaluated_Billets**: Billets resolved through Cedar policy evaluation — available to all identity sources
- **Implicit_Billets**: Billets derived mechanically from IdP group claims when implicit mapping is enabled — prefixed by the IdP source prefix
- **Principal_Entity**: The ephemeral Cedar entity constructed from a validated upstream token, with type determined by identity source

## Requirements

### Requirement 1: Multi-Source Identity Configuration

**User Story:** As a platform operator, I want to configure multiple identity sources, so that both workloads and humans can obtain Quartermaster credentials through their native authentication mechanism.

#### Acceptance Criteria

1. THE system SHALL support configuring multiple identity sources of different types: SPIRE, OIDC IdP, AWS presigned STS, GCP identity token
2. Each OIDC IdP source SHALL be configured with: a unique prefix (alphanumeric + hyphens), OIDC issuer URL, allowed client IDs (audiences), and zero or more implicit claim mappings (each specifying a token claim name, a billet prefix, and an `in_tokens` flag)
3. THE system SHALL validate configuration at startup: prefixes must be unique, issuer URLs must be valid, no prefix conflicts between sources
4. THE Token_Exchange_Endpoint SHALL accept a `subject_token_type` parameter indicating the identity source type:
   - `urn:ietf:params:oauth:token-type:jwt` — SPIRE JWT-SVID
   - `urn:quartermaster:token-type:oidc` — Corporate OIDC token
   - `urn:quartermaster:token-type:aws-presigned-sts` — AWS presigned GetCallerIdentity URL
   - `urn:quartermaster:token-type:gcp-identity` — GCP identity token

### Requirement 2: OIDC IdP Token Validation

**User Story:** As a human user, I want to exchange my corporate IdP token for Quartermaster credentials, so that I can perform operations governed by Quartermaster billets.

#### Acceptance Criteria

1. WHEN an OIDC token is submitted, THE system SHALL identify the IdP source by matching the token's `iss` claim against configured IdP issuer URLs
2. THE system SHALL verify the token signature against the matched IdP's cached JWKS
3. THE system SHALL verify the token's `aud` claim matches one of the allowed client IDs for the matched IdP source
4. THE system SHALL verify the token has not expired
5. IF the token's `iss` does not match any configured IdP source, return HTTP 401
6. IF signature, audience, or expiry validation fails, return HTTP 401
7. THE system SHALL fetch and cache JWKS from each configured IdP's discovery URL, refreshing periodically (default: 1 hour)
8. IF a JWKS refresh fails, THE system SHALL continue using the previously cached JWKS and log a warning
9. IF a JWKS has not refreshed successfully for longer than a configurable staleness period (default: 24 hours), THE system SHALL reject tokens from that IdP with HTTP 503

### Requirement 3: Unified Cedar Evaluation for All Identity Sources

**User Story:** As a platform operator, I want all identity sources to go through the same Cedar policy engine for billet resolution, so that I can write policies that reference attributes from any source and even cross-cut between humans and workloads.

#### Acceptance Criteria

1. AFTER validating an upstream token (regardless of source type), THE system SHALL construct an ephemeral principal entity with source-specific attributes and evaluate Cedar policies for billet resolution
2. FOR SPIRE SVIDs, THE system SHALL construct the principal entity as before (Workload/K8sWorkload/Ec2Workload/GcpWorkload with selectors in context)
3. FOR OIDC IdP tokens, THE system SHALL construct a `HumanIdentity` principal entity with attributes: `email`, `idp_prefix`, `groups` (Set of strings — the flattened union of all configured claim values), and include `source_type: "oidc"` in context
4. FOR AWS presigned STS tokens, THE system SHALL construct an `AwsRoleIdentity` principal entity with attributes: `account_id`, `role_arn`, `role_name`, `role_path`, `session_name`
5. FOR GCP identity tokens, THE system SHALL construct a `GcpIdentity` principal entity with attributes: `project_id`, `email` (service account), `zone`
6. THE Cedar context SHALL include a `source_type` field indicating the identity source (e.g., `"spire"`, `"oidc"`, `"aws-sts"`, `"gcp"`)
7. Cedar policies SHALL be able to condition billet assignment on any attributes from any identity source

### Requirement 4: Implicit Billet Mapping (Optional Per-IdP Claim)

**User Story:** As a platform operator, I want to optionally have specific IdP token claims automatically map to prefixed billets, with control over whether those billets appear in issued tokens or are only used for admin authorization, so that I can onboard teams quickly while controlling what downstream services see.

#### Acceptance Criteria

1. WHEN an IdP source has one or more `implicit_claims` entries configured, THE system SHALL derive billets from each configured claim: one billet per claim value, prefixed with the claim mapping's `billet_prefix` and a colon (e.g., claim value `billing-ops` with prefix `okta-group` → billet `okta-group:billing-ops`)
2. FOR EACH implicit claim mapping, THE `in_tokens` flag SHALL control whether the derived billets appear in issued JWTs and certificates:
   - `in_tokens = true`: implicit billets are included in the issued JWT's `billets` claim and in certificate URI SANs
   - `in_tokens = false`: implicit billets are used for admin Cedar evaluation (control plane authorization) but stripped from the issued JWT and certificate
3. Implicit billet derivation SHALL NOT require the billet to exist in the quartermaster-billets table — these billets exist by virtue of the IdP asserting the claim value
4. WHEN an IdP source has no `implicit_claims` entries, NO implicit billets SHALL be derived — billet resolution is purely Cedar-evaluated
5. Implicit billets and Cedar-evaluated billets MAY coexist — the final token contains the union of Cedar-evaluated billets AND implicit billets where `in_tokens = true`
6. ALL implicit billets (regardless of `in_tokens` flag) SHALL be available as Cedar principals during admin authorization evaluation
7. Multiple claim mappings on the same IdP source SHALL produce independent billet sets that are unioned together

### Requirement 5: Implicit Billet Prefix Enforcement

**User Story:** As a security engineer, I want implicit billet prefixes to be reserved so that Cedar evaluation cannot produce billets that impersonate an IdP source.

#### Acceptance Criteria

1. THE system SHALL maintain a set of reserved prefixes derived from all `billet_prefix` values across all configured implicit claim mappings
2. AFTER Cedar evaluation resolves billets for ANY identity source, THE system SHALL strip any billets from the Cedar result whose names start with a reserved implicit prefix — Cedar cannot mint implicit billets
3. THE Admin API SHALL reject `POST /admin/billets` where the billet name starts with a reserved implicit prefix, returning HTTP 400
4. ONLY the implicit mapping path (claim values from the owning IdP) SHALL produce billets with that claim mapping's prefix
5. IF an IdP source has no `implicit_claims` entries, none of its prefixes are reserved — Cedar policies and the admin API may freely use billet names with that IdP's prefix

### Requirement 6: Human Identity in Quartermaster JWT

**User Story:** As a downstream service, I want to know the identity type and source attributes of the token holder, so that I can make informed access decisions beyond billet checks.

#### Acceptance Criteria

1. WHEN a Quartermaster JWT is issued from any identity source, THE Token_Exchange_Endpoint SHALL include an `identity` claim with at minimum a `type` field
2. FOR SPIRE SVID exchanges: `identity.type` = `"workload"`, `identity.spiffe_id` = the SPIFFE ID
3. FOR OIDC IdP exchanges: `identity.type` = `"human"`, `identity.email` = email claim, `identity.idp` = IdP prefix, `identity.groups` = raw group list
4. FOR AWS presigned STS exchanges: `identity.type` = `"aws_role"`, `identity.account_id`, `identity.role_arn`
5. FOR GCP identity token exchanges: `identity.type` = `"gcp_workload"`, `identity.project_id`, `identity.email`
6. THE `sub` claim SHALL be formatted per source type:
   - SPIRE: the SPIFFE ID (unchanged)
   - OIDC: `human:<email>`
   - AWS STS: `aws:<account_id>:<role_name>`
   - GCP: `gcp:<project_id>:<service_account_email>`

### Requirement 7: Cedar Schema Extension for Multi-Source Identity

**User Story:** As a policy author, I want typed entity definitions for each identity source, so that I can write policies targeting specific source types with their available attributes.

#### Acceptance Criteria

1. THE Cedar schema SHALL include a `HumanIdentity` entity type with attributes: `email` (String), `idp_prefix` (String), `groups` (Set of String)
2. THE Cedar schema SHALL include an `AwsRoleIdentity` entity type with attributes: `account_id` (String), `role_arn` (String), `role_name` (String), `role_path` (String)
3. THE Cedar schema SHALL include a `GcpIdentity` entity type with attributes: `project_id` (String), `email` (String), `zone` (String)
4. THE `assumeBillet` action's `principalTypes` SHALL be extended to include: `HumanIdentity`, `AwsRoleIdentity`, `GcpIdentity` (in addition to existing workload types)
5. ALL admin actions SHALL also accept these new principal types — a human holding billets can perform admin operations

### Requirement 8: AWS Presigned STS Token Exchange

**User Story:** As a workload running on AWS without SPIRE, I want to prove my identity using a presigned GetCallerIdentity request, so that I can obtain Quartermaster credentials using only my native AWS credentials.

#### Acceptance Criteria

1. WHEN a presigned STS URL is submitted as `subject_token` with type `urn:quartermaster:token-type:aws-presigned-sts`, THE system SHALL call the presigned URL and parse the response
2. THE system SHALL extract: `Account`, `Arn`, and `UserId` from the STS response
3. THE system SHALL parse the ARN to extract: account_id, role_name, role_path, session_name
4. THE system SHALL construct an `AwsRoleIdentity` principal entity with these attributes for Cedar evaluation
5. THE presigned URL SHALL be validated: must target `sts.amazonaws.com` (or regional STS endpoint), must use `GetCallerIdentity` action, must not be expired
6. IF the presigned URL is invalid or the STS call returns an error, return HTTP 401

### Requirement 9: GCP Identity Token Exchange

**User Story:** As a workload running on GCP without SPIRE, I want to prove my identity using a GCP identity token, so that I can obtain Quartermaster credentials using only my native GCP credentials.

#### Acceptance Criteria

1. WHEN a GCP identity token is submitted with type `urn:quartermaster:token-type:gcp-identity`, THE system SHALL verify the token signature against Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`)
2. THE system SHALL verify the token's `aud` claim matches Quartermaster's configured issuer URL
3. THE system SHALL extract: `sub` (service account unique ID), `email` (service account email), `google.compute_engine.project_id`, `google.compute_engine.zone` from the token claims
4. THE system SHALL construct a `GcpIdentity` principal entity with these attributes for Cedar evaluation
5. IF signature or audience validation fails, return HTTP 401

### Requirement 10: Audit Logging for All Identity Sources

**User Story:** As a security auditor, I want token exchange events logged with source-specific identity context, so that I can trace credential issuance regardless of the upstream identity type.

#### Acceptance Criteria

1. ALL token exchange audit events SHALL include: `source_type` (spire, oidc, aws-sts, gcp), the identity-source-specific subject identifier, resolved billets (both Cedar-evaluated and implicit), target audience, timestamp, and JTI
2. FOR OIDC exchanges, audit logs SHALL include: email, IdP prefix, and group list
3. FOR AWS STS exchanges, audit logs SHALL include: account_id, role_arn
4. FOR GCP exchanges, audit logs SHALL include: project_id, service_account_email
5. Audit logs SHALL indicate which billets were Cedar-evaluated vs. implicitly mapped


---

## Integration with Existing Design

This spec generalizes the current SPIRE-only identity validation layer into a pluggable multi-source system. The following existing components and interfaces must be refactored:

### 1. Identity Validation Layer (replaces `domain/svid/`)

The existing `Validator` trait (which only validates SPIRE JWT-SVIDs and returns `Claims { spiffe_id, trust_domain, ... }`) is replaced by a source-dispatching layer:

- A top-level `IdentityDispatcher` receives the `subject_token` and `subject_token_type`, routes to the appropriate source-specific validator, and returns a generic `AuthenticatedIdentity` enum.
- The SPIRE SVID validator becomes one implementation behind this dispatcher.
- Each source-specific validator is responsible for signature verification, expiry checks, and claim extraction.
- The `domain/svid/` module becomes `domain/identity/` with sub-modules per source type.

### 2. Billet Resolver Input (replaces SPIFFE-specific `ResolverInput`)

The current `ResolverInput` struct has SPIRE-specific fields (`spiffe_id`, `trust_domain`, `selectors`). This generalizes to accept an `AuthenticatedIdentity` enum:

- The resolver receives the authenticated identity (any source type) + audience + request metadata.
- It delegates to the appropriate entity builder based on identity type.
- Selector enrichment (SPIRE Server API call) is conditional — only invoked for SPIRE-sourced identities.
- For other sources, attributes come directly from the validated token claims.

### 3. Entity Builder (generalized from selector-based platform detection)

The current entity builder detects platform type from SPIRE selector prefixes. This becomes one of several entity construction paths:

- **SPIRE**: existing logic (fetch selectors → detect platform → build K8sWorkload/Ec2Workload/GcpWorkload/Workload)
- **OIDC IdP**: build `HumanIdentity` entity from token claims (email, groups, idp_prefix)
- **AWS presigned STS**: build `AwsRoleIdentity` from STS response (account_id, role_arn, role_name, role_path)
- **GCP identity token**: build `GcpIdentity` from token claims (project_id, email, zone)

### 4. Cedar Evaluation Path (shared, unchanged)

After entity construction, the flow is identical regardless of source:
- Construct ephemeral principal entity
- Evaluate against all known billets via `batch_is_authorized`
- Filter Allow decisions
- (If implicit mapping enabled for this source) union with implicit billets
- Issue JWT + optional cert

### 5. Cache Key Generalization

The cache is currently keyed by `spiffe_id + audience`. This generalizes to `subject + audience` where `subject` is the issued JWT's `sub` claim (format varies by source — see Requirement 6).

### 6. Rate Limiter Key Generalization

Rate limiting is currently per-SPIFFE-ID. This generalizes to per-`subject` (the source-specific identifier).

### 7. Audit Event Generalization

The `AuditEvent` struct's `spiffe_id: String` field becomes a generic `subject: String` + `source_type: String`.

### 8. JWKS Management (new component)

A new `JwksManager` component manages signing keys for multiple sources:
- SPIRE trust bundle (loaded from file/socket, refreshed via SPIRE Workload API)
- Each configured OIDC IdP (fetched from discovery URL, refreshed periodically)
- Google's JWKS (for GCP identity tokens, `https://www.googleapis.com/oauth2/v3/certs`)
- Each source has its own refresh cadence and staleness threshold

### 9. SPIRE Becomes Optional

SPIRE is no longer a hard dependency. If no SPIRE source is configured, the `spireapi/` module is not initialized, the SPIRE trust bundle is not loaded, and the health check does not require it. At least one identity source must be configured.

### 10. Token Exchange Handler Dispatch

The handler currently hardcodes the SVID validation flow. It becomes:

```
Parse subject_token_type
    → dispatch to IdentityDispatcher
    → receive AuthenticatedIdentity
    → build principal entity (source-specific)
    → Cedar evaluation (shared)
    → implicit billet mapping (if applicable)
    → token issuance (shared)
```

---

## Configuration Format

The full configuration file with multi-source identity support:

```toml
[quartermaster]
issuer = "https://quartermaster.example.com"
token_ttl = "5m"            # or "1h", "12h" — configurable per deployment

[server]
addr = "0.0.0.0:8443"
admin_addr = "0.0.0.0:8444"  # optional separate listener for admin API

[dynamo]
region = "us-east-1"
policies_table = "quartermaster-policies"
billets_table = "quartermaster-billets"
policy_sync_interval = "30s"

[signing]
algorithm = "ES256"
key_path = "/etc/quartermaster/keys/signing.pem"

[ca]
key_path = "/etc/quartermaster/keys/ca.key.pem"
cert_path = "/etc/quartermaster/keys/ca.cert.pem"
issuer_cn = "Quartermaster CA"
cert_ttl = "5m"

[cache]
backend = "memory"           # "memory" or "redis"
ttl = "5m"                   # matches token_ttl

[cache.redis]                # only if backend = "redis"
addr = "redis:6379"
db = 0

[rate_limit]
per_identity = 10            # requests per minute per subject

# ─── Identity Sources ────────────────────────────────────────────────────────

# SPIRE (optional — omit entire section if not using SPIRE)
[identity.spire]
trust_domain = "example.com"
jwks_path = "/run/spire/agent/jwks.json"     # or URL
server_addr = "unix:///run/spire/server/api.sock"  # for selector enrichment
audience = "quartermaster.example.com"        # expected audience in SVIDs

# Corporate OIDC IdPs (zero or more)
[[identity.oidc]]
prefix = "okta"
issuer = "https://mycompany.okta.com/oauth2/default"
client_ids = ["0oa1abc2def3ghi4j5k6"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

# Implicit billet mapping — zero or more claim mappings per IdP
# Each maps a token claim (array of strings) to prefixed billets
[[identity.oidc.implicit_claims]]
claim = "groups"                              # token claim name
billet_prefix = "okta-group"                  # billets become okta-group:<value>
in_tokens = false                             # used for admin auth only, stripped from issued JWTs

[[identity.oidc.implicit_claims]]
claim = "roles"                               # a second claim from the same IdP
billet_prefix = "okta-role"                   # billets become okta-role:<value>
in_tokens = true                              # these DO appear in issued JWTs

[[identity.oidc]]
prefix = "azuread"
issuer = "https://login.microsoftonline.com/tenant-id/v2.0"
client_ids = ["app-client-id-1", "app-client-id-2"]
jwks_refresh_interval = "1h"
max_staleness = "24h"
# No implicit_claims blocks → no implicit mapping, Cedar evaluation only

# AWS Presigned STS (optional — omit if not supporting this source)
[identity.aws_sts]
enabled = true
allowed_accounts = ["123456789012", "987654321098"]  # optional: restrict to specific accounts
# No additional config — verification is calling the presigned URL

# GCP Identity Tokens (optional — omit if not supporting this source)
[identity.gcp]
enabled = true
audience = "quartermaster.example.com"        # expected audience in GCP tokens
allowed_projects = ["my-project-123"]         # optional: restrict to specific projects
jwks_refresh_interval = "1h"
max_staleness = "24h"
```

### Configuration Rules

1. At least one identity source MUST be configured. Startup fails if all sources are absent/disabled.
2. IdP prefixes (the top-level `prefix` on each `[[identity.oidc]]` block) MUST be unique across all configured OIDC sources.
3. Implicit claim `billet_prefix` values MUST be unique across ALL implicit claim mappings across ALL IdP sources. No two claim mappings may share a billet prefix.
4. IdP prefixes and billet prefixes MUST match the pattern `[a-z0-9][a-z0-9-]*` (lowercase alphanumeric + hyphens, no leading hyphen).
5. The `in_tokens` flag defaults to `true`. When `false`, implicit billets derived from that claim are used for admin authorization only and stripped from issued JWTs/certs.
6. All `billet_prefix` values from `implicit_claims` entries become reserved — the admin API rejects billet creation with those prefixes, and Cedar evaluation results are stripped of billets with those prefixes.
7. `allowed_accounts` (AWS) and `allowed_projects` (GCP) are optional allowlists. If omitted, any account/project is accepted. If present, tokens from unlisted accounts/projects are rejected with 401.
8. SPIRE's `server_addr` is optional. If omitted, selector enrichment is disabled (billet resolution proceeds without selectors, equivalent to an empty selector set).
9. A single IdP source may have zero `implicit_claims` entries (pure Cedar evaluation) or multiple (each claim independently mapped to its own billet prefix with its own `in_tokens` setting).

### Relationship to Existing Config

The current `SpireConfig` block becomes `[identity.spire]`. The current `AvpConfig` is already removed (replaced by `[dynamo]`). All other config blocks (signing, ca, cache, rate_limit, server) remain unchanged except `rate_limit.per_workload` is renamed to `rate_limit.per_identity`.
