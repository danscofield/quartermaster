# Requirements Document — Uniform Resource Scope Validation

## Introduction

This spec extends resource scope validation to cover ALL policy types (not just `assumeBillet`). The invariant is simple: **all policies stored under billet X must have `resource == Billet::"X"`**. A billet fully controls its own trust ("who can assume me") and its own management ("who can manage me"). No billet can unilaterally grant itself access to another billet — the target billet must authorize it.

This replaces the current behavior where resource scope validation only applies to `assumeBillet` policies, and admin action policies are unconstrained.

## Glossary

- **Resource-Centric Model**: The authorization model where the resource (target billet) determines who can act on it. All policies governing a billet are stored under that billet.
- **System Billet**: `quartermaster-admin` or `quartermaster-guardrails` — exempt from resource scope validation, trusted to issue policy with unconstrained resource scope.

## Requirements

### Requirement 1: Uniform Resource Scope Validation

**User Story:** As a security engineer, I want all policies stored under a billet to be about that billet, so that each billet is the sole authority over its own trust and management.

#### Acceptance Criteria

1. WHEN a policy is created or updated under `/admin/billets/{name}/policies`, THE system SHALL validate that the policy's resource scope references only `Billet::"<name>"` where `<name>` matches the owning billet — regardless of whether the action is `assumeBillet` or an admin action
2. IF the policy has an unconstrained resource (bare `resource`), THE system SHALL reject with HTTP 400: "policies must specify resource == Billet::<owning billet>; unconstrained resource is not allowed"
3. IF the policy's resource scope references a different billet, THE system SHALL reject with HTTP 400: "resource scope references billet '<other>' but policy belongs to billet '<name>'"
4. THE validation SHALL apply to all `permit` and `forbid` statements in the submitted policy
5. THE validation SHALL apply on both `create` and `update` operations

### Requirement 2: System Billet Exemption

**User Story:** As a platform operator, I want system billets to issue globally-scoped policies, so that bootstrap admin and guardrails can operate across all billets.

#### Acceptance Criteria

1. WHEN the owning billet is `quartermaster-admin`, THE system SHALL skip resource scope validation — policies may have unconstrained resource or reference any billet
2. WHEN the owning billet is `quartermaster-guardrails`, THE system SHALL skip resource scope validation — guardrail `forbid` policies intentionally target broad resource scopes
3. THE set of exempt system billets SHALL be configurable (default: `["quartermaster-admin", "quartermaster-guardrails"]`)

### Requirement 3: Policy Semantics Under the Resource-Centric Model

**User Story:** As a platform operator, I want a clear mental model for what policies under a billet mean.

#### Semantics

All policies stored under `/admin/billets/X/policies` answer questions about billet X:

| Action type | Question answered | Example |
|---|---|---|
| `assumeBillet` | "Who can become X?" | `permit(principal, action == Action::"assumeBillet", resource == Billet::"X") when { ... }` |
| `createPolicy` | "Who can add policies to X?" | `permit(principal == Billet::"ops-team", action == Action::"createPolicy", resource == Billet::"X")` |
| `updatePolicy` | "Who can modify X's policies?" | Same pattern |
| `deletePolicy` | "Who can remove policies from X?" | Same pattern |
| `updateBillet` | "Who can edit X's metadata?" | Same pattern |
| `deleteBillet` | "Who can delete X?" | Same pattern |
| `readBillet` | "Who can view X?" | Same pattern |

The *principal* in these policies can be any billet — that's how cross-billet management works. But the *resource* is always X.

#### Acceptance Criteria

1. THE admin API documentation SHALL describe this model: policies under a billet define who can interact with that billet
2. THE `GET /admin/billets/{name}` response (which includes policies) effectively shows the billet's full access control list

### Requirement 4: Granting Cross-Billet Management

**User Story:** As a platform operator, I want to grant `billing-ops` the ability to manage `billing-writer`'s policies, so that teams can delegate administration.

#### Flow

1. An operator with `createPolicy` access on `billing-writer` (e.g., via `quartermaster-admin`) creates:
   ```cedar
   permit(
       principal == Quartermaster::Billet::"billing-ops",
       action in [Action::"createPolicy", Action::"updatePolicy", Action::"deletePolicy"],
       resource == Quartermaster::Billet::"billing-writer"
   );
   ```
2. This policy is stored under `/admin/billets/billing-writer/policies` (resource = billing-writer ✓)
3. Now `billing-ops` can manage `billing-writer`'s policies

#### Acceptance Criteria

1. THE system SHALL allow any billet to appear as principal in policies stored under another billet — the resource scope validation checks *resource*, not *principal*
2. THE principal in admin action policies is not constrained to the owning billet — it's the *resource* that must match

### Requirement 5: Existing Code Change

**User Story:** As a developer, I want to understand what changes in `PolicyCrudService`.

#### Acceptance Criteria

1. THE existing `validate_resource_scope` function SHALL be modified to remove the `if !action_is_assume_billet { continue; }` bypass — validation now applies to ALL policies regardless of action
2. Policies with actions other than `assumeBillet` SHALL be validated with the same resource scope check: resource must reference the owning billet
3. THE system billet exemption (skip validation when owning billet is in the exempt list) SHALL be checked *before* resource scope validation
4. THE existing check `action_is_assume_billet` in `validate_resource_scope` SHALL be removed — it is no longer needed since all actions are validated uniformly

### Requirement 6: Existing Policy Compatibility

**User Story:** As a platform operator upgrading an existing deployment, I want clarity on how existing policies are handled.

#### Acceptance Criteria

1. Validation applies only to newly created or updated policies — existing policies in the DataStore are not retroactively rejected
2. The PolicySyncService loads and evaluates all policies regardless of scope validity — enforcement is at write time only
3. A migration guide SHOULD recommend auditing existing admin action policies that reference resources other than their owning billet
