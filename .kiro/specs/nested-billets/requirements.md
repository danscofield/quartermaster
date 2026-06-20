# Requirements Document — Nested Billets API & Scoped Admin Authorization

## Introduction

This spec restructures the Quartermaster admin API so that policies are nested under their owning billet, introduces cascade deletion, scoped per-billet admin authorization, and changes the billet existence model from "derived from policies" to "explicitly created." It also updates the DynamoDB schema to partition policies by billet.

## Glossary

- **Owning_Billet**: The billet that a policy belongs to. A policy's Cedar `resource` scope must reference only its owning billet. Policies are stored under their owning billet's partition in DynamoDB.
- **Cascade_Delete**: Deleting a billet removes both its metadata record and all policies stored in its partition.
- **Resource_Scope_Validation**: The check ensuring a policy's Cedar statement references only its owning billet in the `resource` scope.

## Requirements

### Requirement 1: Billet Metadata Update

**User Story:** As a platform operator, I want to update a billet's metadata (description, associated cloud roles) without deleting and recreating it, so that I can evolve billet definitions incrementally.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a PUT request to `/admin/billets/{name}`, THE Control_Plane SHALL update the billet's metadata in the quartermaster-billets DynamoDB table
2. THE PUT request SHALL accept a JSON body with optional fields: `description`, `associated_aws_roles`, `associated_gcp_sas`
3. WHEN the billet exists and the update succeeds, THE Control_Plane SHALL return HTTP 200 with the updated billet metadata in the response body
4. IF the specified billet name does not exist in the quartermaster-billets table, THEN THE Control_Plane SHALL return HTTP 404
5. THE Control_Plane SHALL evaluate admin authorization for the `updateBillet` action with the target billet as the resource before permitting the update

### Requirement 2: Billet Response Includes Attached Policies

**User Story:** As a platform operator, I want to see a billet's metadata and its attached policies in a single request, so that I can understand the full billet definition at a glance.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a GET request to `/admin/billets/{name}`, THE Control_Plane SHALL return the billet's metadata AND a list of all policies attached to that billet
2. THE response body SHALL include: `name`, `description`, `associated_aws_roles`, `associated_gcp_sas`, and a `policies` array containing each policy's `id`, `statement`, and `description`
3. IF the billet exists but has no attached policies, THE `policies` array SHALL be empty

### Requirement 3: Cascade Deletion

**User Story:** As a platform operator, I want deleting a billet to remove all of its attached policies, so that I don't leave orphaned policies that reference a nonexistent billet.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a DELETE request to `/admin/billets/{name}`, THE Control_Plane SHALL delete the billet metadata record from the quartermaster-billets table AND all policy records with partition key matching that billet name from the quartermaster-policies table
2. THE deletion SHALL be atomic from the caller's perspective — if the billet delete succeeds, all attached policies are also removed
3. WHEN the cascade delete succeeds, THE Control_Plane SHALL return HTTP 204 with no response body
4. IF the specified billet name does not exist, THEN THE Control_Plane SHALL return HTTP 404
5. THE Control_Plane SHALL NOT allow deletion of the `quartermaster-admin` billet
6. THE Control_Plane SHALL evaluate admin authorization for the `deleteBillet` action with the target billet as the resource before permitting the delete

### Requirement 4: Policies Nested Under Billets — Create

**User Story:** As a platform operator, I want to create policies scoped to a specific billet, so that each policy's ownership and purpose is clear from the API path.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a POST request to `/admin/billets/{name}/policies`, THE Control_Plane SHALL create a new Cedar policy in the quartermaster-policies DynamoDB table with partition key set to the billet name
2. THE request SHALL require a `statement` field containing a valid Cedar policy statement
3. THE request SHALL accept an optional `description` field
4. BEFORE writing to DynamoDB, THE Control_Plane SHALL verify the billet exists in the quartermaster-billets table. IF the billet does not exist, return HTTP 404
5. BEFORE writing to DynamoDB, THE Control_Plane SHALL parse the Cedar statement and validate that its `resource` scope references only `Billet::"<name>"` where `<name>` matches the billet from the URL path. IF the resource scope references a different billet or is unconstrained for `assumeBillet` actions, return HTTP 400 with a descriptive error
6. BEFORE writing to DynamoDB, THE Control_Plane SHALL validate the Cedar statement is syntactically valid and conforms to the Cedar schema. IF validation fails, return HTTP 400
7. WHEN the policy is created successfully, THE Control_Plane SHALL return HTTP 201 with the policy's `id`, `statement`, and `description` in the response body
8. THE Control_Plane SHALL evaluate admin authorization for the `createPolicy` action with the owning billet as the resource

### Requirement 5: Policies Nested Under Billets — List

**User Story:** As a platform operator, I want to list all policies attached to a specific billet, so that I can audit the rules governing that billet's assignment.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a GET request to `/admin/billets/{name}/policies`, THE Control_Plane SHALL return all policies with partition key matching that billet name from the quartermaster-policies table
2. THE response SHALL be HTTP 200 with a JSON array of policy objects, each containing `id`, `statement`, and `description`
3. IF the billet does not exist, THE Control_Plane SHALL return HTTP 404
4. IF the billet exists but has no policies, THE response SHALL be HTTP 200 with an empty array

### Requirement 6: Policies Nested Under Billets — Get

**User Story:** As a platform operator, I want to retrieve a specific policy by ID within a billet, so that I can inspect its current statement.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a GET request to `/admin/billets/{name}/policies/{id}`, THE Control_Plane SHALL return the policy matching the billet name (partition key) and policy ID (sort key)
2. THE response SHALL be HTTP 200 with the policy's `id`, `statement`, and `description`
3. IF the billet does not exist or the policy ID does not exist within that billet, THE Control_Plane SHALL return HTTP 404

### Requirement 7: Policies Nested Under Billets — Update

**User Story:** As a platform operator, I want to update an existing policy's statement, so that I can modify billet assignment rules without deleting and recreating.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a PUT request to `/admin/billets/{name}/policies/{id}`, THE Control_Plane SHALL update the policy's statement and/or description in the quartermaster-policies DynamoDB table
2. THE request SHALL require a `statement` field containing the new Cedar policy statement
3. BEFORE writing, THE Control_Plane SHALL validate the resource scope matches the owning billet (same validation as create). Return HTTP 400 if mismatched
4. BEFORE writing, THE Control_Plane SHALL validate Cedar syntax and schema conformance. Return HTTP 400 if invalid
5. WHEN the update succeeds, THE Control_Plane SHALL return HTTP 200 with the updated policy metadata
6. IF the billet or policy does not exist, THE Control_Plane SHALL return HTTP 404
7. THE Control_Plane SHALL evaluate admin authorization for the `updatePolicy` action with the owning billet as the resource

### Requirement 8: Policies Nested Under Billets — Delete

**User Story:** As a platform operator, I want to delete a specific policy from a billet, so that I can remove outdated assignment rules.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a DELETE request to `/admin/billets/{name}/policies/{id}`, THE Control_Plane SHALL remove the policy record from the quartermaster-policies DynamoDB table
2. WHEN the deletion succeeds, THE Control_Plane SHALL return HTTP 204 with no response body
3. IF the billet or policy does not exist, THE Control_Plane SHALL return HTTP 404
4. THE Control_Plane SHALL evaluate admin authorization for the `deletePolicy` action with the owning billet as the resource

### Requirement 9: DynamoDB Schema — Policies Partitioned by Billet

**User Story:** As a platform operator, I want policies stored partitioned by their owning billet, so that listing and deleting a billet's policies is efficient.

#### Acceptance Criteria

1. THE quartermaster-policies DynamoDB table SHALL use `billet_name` (String) as the partition key and `policy_id` (String, UUID) as the sort key
2. THE PolicySyncService SHALL perform a full table scan of quartermaster-policies to build the in-memory PolicySet (scanning across all partitions)
3. THE `list_policies_for_billet` operation SHALL use a DynamoDB Query on the partition key (not a scan)
4. THE `delete_billet_cascade` operation SHALL query all policies in the billet's partition and delete them via BatchWriteItem, then delete the billet metadata record

### Requirement 10: Billet Existence Model

**User Story:** As a platform operator, I want billets to be explicitly created resources that must exist before policies can reference them, so that the system has a clear source of truth for what billets exist.

#### Acceptance Criteria

1. THE quartermaster-billets DynamoDB table SHALL be the source of truth for which billets exist
2. THE PolicySyncService SHALL scan the quartermaster-billets table on each sync cycle to maintain the in-memory set of known billet names
3. THE known billet set used for `batch_is_authorized` (the set of resources to evaluate against) SHALL come from the quartermaster-billets table, NOT from parsing policy resource scopes
4. THE Control_Plane SHALL reject policy creation (`POST /admin/billets/{name}/policies`) if the owning billet does not exist in the quartermaster-billets table

### Requirement 11: Scoped Admin Authorization

**User Story:** As a platform operator, I want to grant admin permissions on a per-billet basis, so that teams can manage their own billets without having access to the entire system.

#### Acceptance Criteria

1. ALL admin actions (createBillet, updateBillet, deleteBillet, readBillet, createPolicy, updatePolicy, deletePolicy) SHALL use the target billet as the Cedar resource in authorization evaluation
2. Cedar policies SHALL be able to scope admin permissions to specific billets (e.g., `resource == Quartermaster::Billet::"billing-writer"`)
3. THE Cedar schema SHALL include an `updateBillet` action with `principal: [Billet]` and `resource: [Billet]`
4. THE bootstrap `quartermaster-admin` policy SHALL grant all admin actions on all resources (unconstrained resource scope)

### Requirement 12: Handler File Structure

**User Story:** As a developer, I want admin handlers organized by resource hierarchy, so that the code structure mirrors the API structure.

#### Acceptance Criteria

1. ALL admin billet and policy handlers SHALL be implemented in a single handler module (`admin_billets`) since policies are a sub-resource of billets
2. THE axum router SHALL register nested routes: `/admin/billets`, `/admin/billets/:name`, `/admin/billets/:name/policies`, `/admin/billets/:name/policies/:id`
