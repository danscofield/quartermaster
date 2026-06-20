# Requirements Document — Cross-Cloud Backend Abstraction

## Introduction

This spec abstracts the two cloud-specific backends in Quartermaster (data store and signing/CA key management) behind pluggable traits with multiple implementations. This enables deployment on AWS, GCP, or local/dev environments without code changes — only configuration differs.

## Glossary

- **DataStore**: The abstract interface for persisting billets and policies. Implementations: DynamoDB, Google Cloud Bigtable/Firestore.
- **KeyManager**: The abstract interface for cryptographic signing and CA operations. Implementations: in-memory (dev/test), AWS KMS, GCP Cloud KMS.

## Requirements

### Requirement 1: Data Store Abstraction

**User Story:** As a platform operator, I want to deploy Quartermaster on GCP without depending on DynamoDB, so that I can use cloud-native storage in each environment.

#### Acceptance Criteria

1. THE system SHALL define a `DataStore` trait abstracting all persistent storage operations (billet CRUD, policy CRUD, listing, cascade delete, health check)
2. THE existing `DynamoClient` trait methods SHALL be refactored into the `DataStore` trait with cloud-agnostic naming (no DynamoDB-specific terminology in the trait interface)
3. THE system SHALL support the following `DataStore` implementations:
   - `dynamodb` — AWS DynamoDB (existing behavior)
   - `firestore` — Google Cloud Firestore (document-oriented, serverless, strong consistency)
   - `local` — File-backed local storage (JSON files on disk, for dev/test/single-node)
4. THE implementation SHALL be selected via configuration:
   ```toml
   [datastore]
   backend = "dynamodb"   # or "firestore" or "local"

   [datastore.dynamodb]
   region = "us-east-1"
   billets_table = "quartermaster-billets"
   policies_table = "quartermaster-policies"

   [datastore.firestore]
   project = "my-project"
   collection_prefix = "quartermaster"   # → quartermaster-billets, quartermaster-policies

   [datastore.local]
   path = "/var/lib/quartermaster/data"   # directory for persisted JSON files
   ```
5. THE `DataStore` trait SHALL expose the same operations regardless of backend:
   - Billet: create, get, update, delete_cascade, list
   - Policy: create, get, update, delete, list_for_billet, list_all
   - Health: ping
6. ALL implementations SHALL provide strong consistency on writes (read-after-write guaranteed)
7. THE `PolicySyncService` SHALL work identically regardless of backend — it calls `list_all_policies()` and `list_billets()` on the trait

### Requirement 2: Firestore Implementation

**User Story:** As a GCP-native operator, I want Quartermaster to store policies and billets in Firestore, so that I don't need cross-cloud dependencies.

#### Acceptance Criteria

1. THE Firestore implementation SHALL use one collection per resource type:
   - `{prefix}-billets` — documents keyed by billet name
   - `{prefix}-policies` — flat documents keyed by `{billet_name}__{policy_id}` (double-underscore separator), each containing a `billet_name` field for query filtering
2. `list_policies_for_billet` SHALL use a Firestore query filtering on the billet_name field (or collection group query with prefix)
3. `delete_cascade` SHALL delete the billet document and all policy documents with matching billet_name in a batch write
4. THE Firestore implementation SHALL use server timestamps for `created_at` and `updated_at`

### Requirement 3: Local File-Backed Implementation

**User Story:** As a developer or edge operator, I want to run Quartermaster without any cloud database dependency, so that I can develop locally, run CI tests without credentials, or deploy on a single node.

#### Acceptance Criteria

1. THE local implementation SHALL persist billets and policies as JSON files on disk in the configured `path` directory
2. THE directory structure SHALL be:
   - `{path}/billets/{name}.json` — one file per billet
   - `{path}/policies/{billet_name}/{policy_id}.json` — one file per policy, nested under owning billet
3. `list_all_policies` SHALL recursively read all policy JSON files across all billet subdirectories
4. `list_policies_for_billet` SHALL read all JSON files in the `{path}/policies/{billet_name}/` directory
5. `delete_cascade` SHALL delete the billet JSON file and the entire `{path}/policies/{billet_name}/` directory
6. THE local implementation SHALL use an in-memory `RwLock` cache for reads, flushed to disk on every write (write-through cache)
7. THE local implementation SHALL create the `path` directory and subdirectories on startup if they do not exist
8. THE local implementation SHALL be the default when no `[datastore]` section is specified in configuration

### Requirement 4: Key Manager Abstraction

**User Story:** As a platform operator, I want signing and CA key operations to work with my cloud's KMS, so that private keys never leave an HSM in production while still supporting fast local development.

#### Acceptance Criteria

1. THE system SHALL define a `KeyManager` trait abstracting cryptographic operations:
   - `sign(payload: &[u8]) -> Result<Vec<u8>, KeyError>` — sign a digest (always local, using in-memory key)
   - `public_key_jwk() -> Result<Jwk, KeyError>` — return the current public key in JWK format
   - `key_id() -> &str` — return the key ID for JWT `kid` header
   - `algorithm() -> Algorithm` — return the signing algorithm (ES256, RS256)
   - `jwks() -> Vec<Jwk>` — return all active public keys (current + overlapping previous)
2. THE system SHALL support the following `KeyManager` implementations:
   - `memory` — static in-memory key from PEM file (dev/test, no rotation)
   - `kms_delegated` — ephemeral key rotated and signed by KMS root (production)
3. THE implementation SHALL be selected via configuration:
   ```toml
   [signing]
   backend = "memory"   # or "kms_delegated"

   [signing.memory]
   key_path = "/etc/quartermaster/keys/signing.pem"

   [signing.kms_delegated]
   rotation_interval = "6h"
   key_overlap = "24h"
   ephemeral_algorithm = "ES256"

   # Choose one KMS backend:
   [signing.kms_delegated.aws_kms]
   key_arn = "arn:aws:kms:us-east-1:123:key/mrk-abc123"
   region = "us-east-1"

   # OR:
   [signing.kms_delegated.gcp_kms]
   key_name = "projects/my-project/locations/global/keyRings/qm/cryptoKeys/signing/cryptoKeyVersions/1"
   ```
4. THE same `KeyManager` trait SHALL be used for both JWT signing and CA certificate signing (separate instances with different keys)
5. CA configuration SHALL mirror signing configuration:
   ```toml
   [ca]
   backend = "memory"   # or "kms_delegated"

   [ca.memory]
   key_path = "/etc/quartermaster/keys/ca.key.pem"
   cert_path = "/etc/quartermaster/keys/ca.cert.pem"

   [ca.kms_delegated]
   rotation_interval = "6h"
   key_overlap = "24h"
   ephemeral_algorithm = "ES256"
   cert_path = "/etc/quartermaster/keys/ca.cert.pem"   # CA cert (public) still on disk

   [ca.kms_delegated.aws_kms]
   key_arn = "arn:aws:kms:us-east-1:123:key/mrk-def456"
   region = "us-east-1"

   # OR:
   [ca.kms_delegated.gcp_kms]
   key_name = "projects/my-project/locations/global/keyRings/qm/cryptoKeys/ca/cryptoKeyVersions/1"
   ```

### Requirement 5: In-Memory Implementation (Existing Behavior)

**User Story:** As a developer, I want to run Quartermaster locally without cloud dependencies for fast iteration.

#### Acceptance Criteria

1. THE in-memory `KeyManager` SHALL load a private key from a PEM file (existing `StaticKeyManager` behavior)
2. THE in-memory `KeyManager` SHALL sign directly in-process with no network calls
3. THE in-memory implementation SHALL be the default when no backend is specified

### Requirement 6: Delegated Signing (KMS-Backed Ephemeral Keys)

**User Story:** As a platform operator, I want HSM-level trust without paying per-signature KMS costs, so that Quartermaster can sign tokens locally using short-lived keys that are themselves signed by a KMS root.

#### Acceptance Criteria

1. THE system SHALL support a `kms_delegated` signing backend where KMS signs a short-lived ephemeral signing key pair, and Quartermaster uses that ephemeral key for all local token/cert signing until the next rotation
2. ON startup and every `rotation_interval` (configurable, default 6 hours), THE system SHALL:
   - Generate a new ephemeral EC P-256 (or configured algorithm) key pair in memory
   - Call KMS once to sign the ephemeral public key (producing a certificate or attestation binding the ephemeral key to the KMS root)
   - Store the new ephemeral key as the active signing key
3. THE JWKS endpoint SHALL serve both the current and previous ephemeral public keys during the overlap window
4. THE overlap window (`key_overlap`) SHALL be configurable (default 24 hours) to accommodate relying parties that cache JWKS aggressively (e.g., AWS STS caches up to 24h)
5. After `key_overlap` duration has elapsed since a key was rotated out, THE system SHALL remove it from the JWKS response
6. ALL Quartermaster instances SHALL use the same active ephemeral key at any given time. The signed ephemeral key SHALL be stored in the DataStore (a record in the billets/policies store or a dedicated key record) so that all instances poll and adopt the same key.
7. IF a new ephemeral key appears in the DataStore, each instance SHALL adopt it as the active signing key within one sync interval
8. THE ephemeral key's `kid` in the JWKS SHALL be derived from the key's public component (e.g., SHA-256 thumbprint) to ensure consistency across instances
9. KMS cost SHALL be bounded: one KMS `Sign` call per rotation interval per cluster (not per instance, not per token)
10. THE configuration SHALL be:
    ```toml
    [signing]
    backend = "kms_delegated"
    rotation_interval = "6h"
    key_overlap = "24h"
    ephemeral_algorithm = "ES256"

    [signing.kms_delegated.aws_kms]
    key_arn = "arn:aws:kms:us-east-1:123:key/mrk-abc123"
    region = "us-east-1"

    # OR for GCP:
    [signing.kms_delegated.gcp_kms]
    key_name = "projects/my-project/locations/global/keyRings/qm/cryptoKeys/root/cryptoKeyVersions/1"
    ```
11. THE same delegated model SHALL apply to CA signing — the CA ephemeral key is signed by a KMS root and rotated on the same schedule
12. IF KMS is unreachable during a rotation attempt, THE system SHALL continue using the current ephemeral key and retry on the next sync interval. The health check SHALL report degraded state if the current key is older than `rotation_interval × 2`

### Requirement 7: Consistent Interface for PolicySyncService and Billet Resolver

**User Story:** As a developer, I want the sync service and billet resolver to work identically regardless of which backends are configured, so that business logic doesn't branch on infrastructure.

#### Acceptance Criteria

1. THE `PolicySyncService` SHALL accept a `Arc<dyn DataStore>` — it calls `list_all_policies()` and `list_billets()` without knowing the backing implementation
2. THE `CedarAuthorizer` SHALL accept a `Arc<dyn KeyManager>` only indirectly (via `SigningManager` trait which wraps `KeyManager`) — evaluation logic is unchanged
3. THE token exchange handler flow SHALL be identical regardless of backend — no conditional logic based on which DataStore or KeyManager is active
4. ALL integration tests SHALL be runnable against any DataStore/KeyManager implementation via test configuration
