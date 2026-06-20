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
2. Each OIDC IdP source SHALL be configured with: a unique prefix (alphanumeric + hyphens), OIDC issuer URL, allowed client IDs (audiences), group claim name (default: `groups`), and a boolean `implicit_mapping_enabled` flag (default: false)
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
3. FOR OIDC IdP tokens, THE system SHALL construct a `HumanIdentity` principal entity with attributes: `email`, `idp_prefix`, `groups` (Set of strings), and any additional configured claims
4. FOR AWS presigned STS tokens, THE system SHALL construct an `AwsRoleIdentity` principal entity with attributes: `account_id`, `role_arn`, `role_name`, `role_path`, `session_name`
5. FOR GCP identity tokens, THE system SHALL construct a `GcpIdentity` principal entity with attributes: `project_id`, `email` (service account), `zone`
6. THE Cedar context SHALL include a `source_type` field indicating the identity source (e.g., `"spire"`, `"oidc"`, `"aws-sts"`, `"gcp"`)
7. Cedar policies SHALL be able to condition billet assignment on any attributes from any identity source

### Requirement 4: Implicit Billet Mapping (Optional Per-IdP)

**User Story:** As a platform operator, I want to optionally have IdP group claims automatically map to prefixed billets without writing Cedar policies, so that I can quickly onboard teams and progressively adopt Cedar-based policies.

#### Acceptance Criteria

1. WHEN an IdP source has `implicit_mapping_enabled: true`, THE system SHALL derive one billet per group claim value, prefixed with the IdP prefix and colon (e.g., group `billing-ops` from IdP prefix `okta` → billet `okta:billing-ops`)
2. Implicit billets SHALL be derived AFTER Cedar evaluation — the final billet set is the union of Cedar-evaluated billets AND implicit billets
3. Implicit billet derivation SHALL NOT require the billet to exist in the quartermaster-billets table — these billets exist by virtue of the IdP asserting group membership
4. WHEN an IdP source has `implicit_mapping_enabled: false` (the default), NO implicit billets SHALL be derived from that source's tokens — billet resolution is purely Cedar-evaluated
5. Implicit billets and Cedar-evaluated billets MAY coexist in the same issued token

### Requirement 5: Implicit Billet Prefix Enforcement

**User Story:** As a security engineer, I want implicit billet prefixes to be reserved so that Cedar evaluation cannot produce billets that impersonate an IdP source.

#### Acceptance Criteria

1. THE system SHALL maintain a set of reserved prefixes derived from all configured IdP sources that have `implicit_mapping_enabled: true`
2. AFTER Cedar evaluation resolves billets for ANY identity source, THE system SHALL strip any billets from the Cedar result whose names start with a reserved implicit prefix — Cedar cannot mint implicit billets
3. THE Admin API SHALL reject `POST /admin/billets` where the billet name starts with a reserved implicit prefix, returning HTTP 400
4. ONLY the implicit mapping path (group claims from the owning IdP) SHALL produce billets with that IdP's prefix
5. IF an IdP source has `implicit_mapping_enabled: false`, its prefix is NOT reserved — Cedar policies and the admin API may freely use billet names with that prefix

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
