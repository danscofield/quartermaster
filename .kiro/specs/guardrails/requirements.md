# Requirements Document — Billet Tags & Global Guardrail Policies

## Introduction

This spec adds key/value tags to billets and introduces a reserved system billet (`quartermaster-guardrails`) whose attached policies serve as global `forbid` rules. These guardrails are written by infrastructure security teams and enforce invariants across the entire system — no `permit` policy can override them. Billet tags are attached as attributes to the Cedar entity at evaluation time, enabling guardrail policies to reason over billet properties without knowing every billet by name.

## Glossary

- **Billet_Tag**: A string in `key:value` format attached to a billet's metadata. Tags are surfaced as a `Set<String>` attribute on the Cedar `Billet` entity at evaluation time.
- **Guardrail_Policy**: A Cedar `forbid` policy attached to the `quartermaster-guardrails` system billet. Guardrail policies apply globally — they are evaluated for every `assumeBillet` and admin action regardless of which billet is the resource.
- **quartermaster-guardrails**: A reserved system billet that holds global `forbid` policies. It cannot be deleted, cannot hold `permit` policies, and its policies apply across all authorization evaluations.

## Requirements

### Requirement 1: Billet Tags

**User Story:** As a platform operator, I want to attach key/value tags to billets, so that Cedar policies can reason over billet properties without referencing specific billet names.

#### Acceptance Criteria

1. THE `quartermaster-billets` DynamoDB table SHALL support a `tags` attribute (StringSet) on each billet record, storing tags in `key:value` format
2. THE Admin API SHALL accept a `tags` field (array of strings) on `POST /admin/billets` and `PUT /admin/billets/{name}` requests
3. EACH tag string MUST conform to the format `key:value` where key and value are non-empty strings containing only alphanumeric characters, hyphens, underscores, and dots
4. THE Admin API SHALL reject tags that do not conform to the format with HTTP 400
5. THE `GET /admin/billets/{name}` and `GET /billets/{name}` responses SHALL include the billet's `tags` array

### Requirement 2: Billet Entity Enrichment at Evaluation Time

**User Story:** As a policy author, I want to reference billet tags in Cedar policies, so that I can write rules that apply to categories of billets.

#### Acceptance Criteria

1. WHEN constructing Cedar entities for billet evaluation (both `assumeBillet` and admin actions), THE system SHALL attach a `tags` attribute (Set of String) to each `Billet` entity using the tags from the billet's cached metadata
2. IF a billet has no metadata record or no tags, THE `tags` attribute SHALL be an empty set
3. THE PolicySyncService SHALL cache billet metadata (including tags) alongside the PolicySet, refreshing on each sync cycle
4. THE Cedar schema SHALL declare the `Billet` entity type with a `tags` attribute:
   ```cedar
   entity Billet = {
       tags: Set<String>,
   };
   ```

### Requirement 3: The `quartermaster-guardrails` System Billet

**User Story:** As an infrastructure security engineer, I want a dedicated system billet for global guardrail policies, so that I can enforce invariants that no other team can override.

#### Acceptance Criteria

1. THE system SHALL reserve the billet name `quartermaster-guardrails` — it is created automatically on first startup (bootstrap) alongside `quartermaster-admin`
2. THE system SHALL NOT allow deletion of the `quartermaster-guardrails` billet (same protection as `quartermaster-admin`)
3. THE `quartermaster-guardrails` billet SHALL only accept `forbid` policies — attempts to attach a `permit` policy SHALL be rejected with HTTP 400 and a descriptive error
4. Policies attached to `quartermaster-guardrails` SHALL have no resource scope restriction — they may reference any billet, use unconstrained resource, or condition on `resource.tags`
5. THE `quartermaster-guardrails` billet SHALL be tagged with `system:true` by default

### Requirement 4: Guardrail Policy Enforcement

**User Story:** As an infrastructure security engineer, I want guardrail policies to be evaluated on every authorization request, so that they act as inviolable constraints regardless of which billet is being assumed or managed.

#### Acceptance Criteria

1. Guardrail policies (attached to `quartermaster-guardrails`) SHALL be included in the PolicySet loaded by the PolicySyncService like any other policy — Cedar's default evaluation semantics ensure `forbid` overrides `permit`
2. NO special evaluation path is required — Cedar's built-in "deny overrides" behavior ensures guardrail `forbid` policies take precedence over any `permit` policy from any other billet
3. Guardrail policies SHALL be effective for both `assumeBillet` evaluations (workload/human billet assignment) AND admin action evaluations (billet/policy management)

### Requirement 5: Guardrail Policy Validation

**User Story:** As the system, I want to ensure only `forbid` policies are attached to the guardrails billet, so that the guardrails billet cannot be used to grant permissions.

#### Acceptance Criteria

1. WHEN a policy is created or updated under `quartermaster-guardrails` (`POST /admin/billets/quartermaster-guardrails/policies` or `PUT .../policies/{id}`), THE system SHALL parse the Cedar statement and verify it contains only `forbid` statements
2. IF the statement contains any `permit` statement, THE system SHALL reject with HTTP 400 and error: "guardrail policies must be forbid-only; permit policies are not allowed on the quartermaster-guardrails billet"
3. `forbid` policies with `when` clauses ARE allowed (conditional guardrails)
4. `forbid` policies with `unless` clauses ARE allowed (guardrails with exceptions)

### Requirement 6: Admin Authorization for Guardrail Management

**User Story:** As an infrastructure security engineer, I want guardrail policy management to require elevated privileges, so that only authorized operators can modify the system-wide constraints.

#### Acceptance Criteria

1. Creating, updating, or deleting policies under `quartermaster-guardrails` SHALL require admin authorization for the corresponding action (`createPolicy`, `updatePolicy`, `deletePolicy`) with `quartermaster-guardrails` as the resource
2. THE bootstrap `quartermaster-admin` policy SHALL grant these actions on `quartermaster-guardrails` (already covered by the unconstrained resource grant)
3. Operators MAY create a dedicated `guardrail-admin` billet with a scoped policy granting only guardrail management:
   ```cedar
   permit(
       principal == Quartermaster::Billet::"guardrail-admin",
       action in [Action::"createPolicy", Action::"updatePolicy", Action::"deletePolicy"],
       resource == Quartermaster::Billet::"quartermaster-guardrails"
   );
   ```

### Requirement 7: Example Guardrail Policies

**User Story:** As documentation for the system, the following example guardrail policies illustrate common usage patterns.

#### Examples (non-normative)

```cedar
// No workload identity can hold a billet tagged as human-only
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource
) when {
    context.source_type == "spire" &&
    resource.tags.contains("human-only")
};

// No human identity can hold a billet tagged as workload-only
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource
) when {
    context.source_type == "oidc" &&
    resource.tags.contains("workload-only")
};

// High-sensitivity billets require production namespace workloads
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource
) when {
    resource.tags.contains("sensitivity:high") &&
    !context.selectors.contains("k8s:ns:production")
};

// Billets tagged as immutable cannot have their policies modified by non-admins
forbid(
    principal,
    action in [
        Quartermaster::Action::"createPolicy",
        Quartermaster::Action::"updatePolicy",
        Quartermaster::Action::"deletePolicy"
    ],
    resource
) when {
    resource.tags.contains("immutable:true")
} unless {
    principal == Quartermaster::Billet::"quartermaster-admin"
};

// No billet can be deleted if it's tagged as critical
forbid(
    principal,
    action == Quartermaster::Action::"deleteBillet",
    resource
) when {
    resource.tags.contains("lifecycle:critical")
} unless {
    principal == Quartermaster::Billet::"quartermaster-admin"
};

// AWS production roles can only be assigned from the production environment
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource
) when {
    resource.tags.contains("env:production") &&
    context.environment != "production"
};
```

### Requirement 8: Bootstrap Behavior

**User Story:** As a platform operator deploying Quartermaster for the first time, I want the guardrails billet to be created automatically, so that I can start writing guardrail policies immediately.

#### Acceptance Criteria

1. ON first startup, IF `quartermaster-guardrails` does not exist in the `quartermaster-billets` table, THE system SHALL create it with: description "System billet for global guardrail (forbid) policies", tags `["system:true"]`
2. ON first startup, IF `quartermaster-admin` does not exist, THE system SHALL create it with: description "Bootstrap admin billet", tags `["system:true"]`
3. THE bootstrap creation SHALL be idempotent — if the billets already exist, no error is raised
