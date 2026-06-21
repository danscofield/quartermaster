# Requirements Document — SPIFFE ID Path Pattern Extraction (Replace SPIRE API Dependency)

## Introduction

This spec replaces the SPIRE Server API dependency with a purely local, configuration-driven approach to extracting workload attributes from SPIFFE IDs. Operators define regex patterns with named capture groups that parse their SPIFFE ID path structure into Cedar principal attributes. This eliminates all network calls to the SPIRE Server on the token exchange hot path.

## Motivation

The current SPIRE API calls (workload entry + parent entry) are:
- Two network round-trips on the hot path
- Dependent on SPIRE Server availability
- Limited to whatever selectors the operator configured on registration entries (not necessarily the metadata Quartermaster cares about)
- Not cryptographically stronger than parsing the SPIFFE ID itself (the SPIFFE ID is already attested)

Since the SPIFFE ID path is attested by SPIRE at issuance time, any metadata encoded in the path is trustworthy. Operators who structure their SPIFFE IDs to include relevant dimensions (namespace, project, environment, etc.) can skip the API call entirely.

## Requirements

### Requirement 1: Path Pattern Configuration

#### Acceptance Criteria

1. THE `[identity.spire]` config section SHALL accept zero or more `[[identity.spire.path_patterns]]` entries, each with a `pattern` field containing a regex with named capture groups
2. Patterns SHALL be evaluated in order against the SPIFFE ID path (the part after `spiffe://<trust_domain>`). First match wins.
3. Named capture groups from the matching pattern SHALL become attributes on the Cedar principal entity (as `String` values)
4. IF no pattern matches, THE principal entity SHALL have no extracted attributes (only `spiffe_id` and `trust_domain` are set)
5. Example config:
   ```toml
   [identity.spire]
   trust_domain = "example.com"
   jwks_path = "/run/spire/agent/jwks.json"
   audience = "quartermaster.example.com"

   [[identity.spire.path_patterns]]
   pattern = "^/env/(?P<environment>[^/]+)/project/(?P<project>[^/]+)/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)$"

   [[identity.spire.path_patterns]]
   pattern = "^/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)/workload/(?P<workload>[^/]+)$"

   [[identity.spire.path_patterns]]
   pattern = "^/agent/(?P<agent_type>[^/]+)/(?P<agent_id>.+)$"
   ```

### Requirement 2: Cedar Entity Construction from Captures

#### Acceptance Criteria

1. THE principal entity type SHALL be `Quartermaster::Workload` for all SPIRE-sourced identities (remove platform-specific subtypes K8sWorkload/Ec2Workload/GcpWorkload — the regex captures supersede platform detection)
2. THE entity SHALL always have attributes: `spiffe_id` (String), `trust_domain` (String)
3. ALL named capture groups from the matched pattern SHALL be added as `String` attributes on the entity
4. THE Cedar schema for `Workload` SHALL use open attributes (tags/record with optional fields) or the schema SHALL be updated to declare the expected attribute names from configured patterns
5. THE `context.selectors` field SHALL be an empty set when path patterns are used (no SPIRE API call means no selectors)

### Requirement 3: Remove SPIRE Server API Dependency

#### Acceptance Criteria

1. WHEN `[[identity.spire.path_patterns]]` is configured, THE system SHALL NOT call the SPIRE Server API for selector enrichment — no `ListEntries` calls, no parent entry fetches
2. THE `server_addr` field in `[identity.spire]` SHALL become irrelevant when path patterns are configured (can be omitted)
3. THE `SelectorEnricher` used for SPIRE identities SHALL be `NoOpSelectorEnricher` when path patterns are configured
4. THE `spireapi/` module and `HttpSpireApiClient` SHALL remain in the codebase for operators who do NOT configure path patterns (legacy mode: still fetches selectors if `server_addr` is present and no path patterns are defined)

### Requirement 4: Legacy Mode Preservation

#### Acceptance Criteria

1. IF `path_patterns` is empty/absent AND `server_addr` is configured, THE system SHALL use the existing `SpireSelectorEnricher` (current behavior with API calls)
2. IF `path_patterns` is empty/absent AND `server_addr` is absent, THE system SHALL use `NoOpSelectorEnricher` (no attributes beyond spiffe_id/trust_domain)
3. IF `path_patterns` is present, `server_addr` is ignored regardless of whether it's set

### Requirement 5: Startup Validation

#### Acceptance Criteria

1. ALL patterns SHALL be compiled at startup. Invalid regex SHALL cause startup failure with a descriptive error
2. Patterns with zero named capture groups SHALL produce a startup warning (valid but useless)
3. Capture group names SHALL be validated as valid Cedar attribute names (alphanumeric + underscore)

### Requirement 6: Cedar Policy Usage

#### Acceptance Criteria

1. Cedar policies SHALL be able to reference captured attributes directly on the principal:
   ```cedar
   permit(principal, action == Action::"assumeBillet", resource == Billet::"prod-billing")
   when {
       principal.environment == "prod" &&
       principal.namespace == "billing"
   };
   ```
2. Policies referencing attributes that don't exist on a principal (because a different pattern matched, or no pattern matched) SHALL evaluate to `false` for that condition (Cedar's standard behavior for missing attributes)
