# Implementation Plan: Cross-Cloud Backend Abstraction

## Overview

This plan implements the `DataStore` and `KeyManager` trait abstractions for Quartermaster, enabling pluggable backends for persistent storage (DynamoDB, Firestore, local file) and cryptographic signing (memory, KMS-delegated). The implementation proceeds incrementally: traits and types first, then each backend implementation, then integration wiring. Each step builds on the previous and ends with integration into the running system.

## Tasks

- [ ] 1. Define DataStore trait, record types, and error model
  - [x] 1.1 Create `src/datastore/mod.rs` module with `DataStoreError` enum, `BilletRecord`, `PolicyRecord`, `EphemeralKeyRecord` structs, and the `DataStore` async trait
    - Define `DataStoreError` with `NotFound`, `Conflict`, `Internal` variants
    - Define `BilletRecord` with fields: name, description, associated_aws_roles, associated_gcp_sas, tags, created_at, updated_at
    - Define `PolicyRecord` with fields: billet_name, policy_id, statement, description, created_at, updated_at
    - Define `EphemeralKeyRecord` with fields: key_id, public_key_pem, private_key_encrypted, kms_attestation, algorithm, created_at, expires_at, purpose
    - Define `#[async_trait] pub trait DataStore: Send + Sync` with all billet, policy, ephemeral key, and ping methods from the design
    - Add `#[cfg_attr(test, mockall::automock)]` to the trait for test mocking
    - Register the module in `src/lib.rs`
    - _Requirements: 1.1, 1.2, 1.5_

  - [ ]* 1.2 Write property test for DataStore CRUD round-trip (Property 1)
    - **Property 1: DataStore CRUD Round-Trip**
    - Generate arbitrary `BilletRecord` and `PolicyRecord` values using proptest
    - Write to a `LocalDataStore` instance, read back, assert field equality (modulo timestamps)
    - **Validates: Requirements 1.6, 3.1**

- [ ] 2. Define configuration model for DataStore and Signing backends
  - [x] 2.1 Create `src/config/backends.rs` with all configuration structs for DataStore and Signing
    - Define `DataStoreConfig` with `backend: DataStoreBackend` enum (Dynamodb, Firestore, Local), optional sub-configs
    - Define `DynamoDbConfig`, `FirestoreConfig`, `LocalStoreConfig` structs
    - Define `SigningBackendConfig` with `backend: SigningBackend` enum (Memory, KmsDelegated), optional sub-configs
    - Define `MemorySigningConfig`, `KmsDelegatedConfig`, `AwsKmsConfig`, `GcpKmsConfig` structs
    - Implement defaults: `Local` for DataStore, `Memory` for Signing
    - Add default value functions for all optional fields (rotation_interval "6h", key_overlap "24h", etc.)
    - Register in `src/config/mod.rs`
    - _Requirements: 1.4, 4.3, 5.3, 6.10_

  - [ ]* 2.2 Write property test for configuration backend selection (Property 5)
    - **Property 5: Configuration Backend Selection**
    - Generate valid TOML config fragments with proptest (varying backend values, missing sections)
    - Parse and assert correct backend enum is selected; assert defaults when section is absent
    - **Validates: Requirements 1.4, 3.8, 4.3, 5.3**

  - [x] 2.3 Integrate new backend config into top-level `Config` struct
    - Add `datastore: Option<DataStoreConfig>` and `signing_backend: Option<SigningBackendConfig>` and `ca_backend: Option<SigningBackendConfig>` to the `Config` struct
    - Keep existing `dynamo`, `signing`, `ca` fields for backward compatibility during migration
    - Update `Config::validate()` to validate new backend config sections when present
    - Update TOML deserialization tests to cover new sections
    - _Requirements: 1.4, 4.3, 4.5_

- [ ] 3. Implement Local file-backed DataStore
  - [x] 3.1 Create `src/datastore/local.rs` implementing `DataStore` for local file storage
    - Define `LocalDataStore` struct wrapping `tokio::sync::RwLock<LocalState>` (in-memory maps for billets and policies)
    - Implement `new(path: PathBuf)` constructor that creates directories and loads existing JSON files into memory
    - Implement all billet CRUD methods: create (conflict check), get, update, delete_cascade (remove billet + all policies + directory), list
    - Implement all policy CRUD methods: create, get, update, delete, list_for_billet, list_all
    - Implement ephemeral key operations: put, get_active, delete_expired
    - Implement `ping()` (always Ok for local)
    - Use write-through cache: every write serializes to JSON, writes to temp file, atomically renames
    - Use directory structure: `{path}/billets/{name}.json`, `{path}/policies/{billet_name}/{policy_id}.json`, `{path}/keys/`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 3.2 Write property test for cascade delete completeness (Property 3)
    - **Property 3: Cascade Delete Completeness**
    - Generate billets with random numbers of policies (0 to N), write them, cascade delete, assert get_billet returns None and list_policies_for_billet returns empty
    - **Validates: Requirements 2.3, 3.5**

  - [ ]* 3.3 Write property test for listing correctness (Property 4)
    - **Property 4: Listing Correctness**
    - Generate random multi-billet datasets, write to LocalDataStore, verify list_all_policies returns exactly all written policies, and list_policies_for_billet returns correct per-billet subsets
    - **Validates: Requirements 3.3, 3.4**

  - [ ]* 3.4 Write property test for local file path determinism (Property 10)
    - **Property 10: Local File Path Determinism**
    - Generate valid billet names and policy IDs (alphanumeric, hyphen, underscore), verify constructed paths match `{base}/billets/{name}.json` and `{base}/policies/{billet_name}/{policy_id}.json`
    - **Validates: Requirements 3.2**

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement DynamoDB DataStore adapter
  - [x] 5.1 Create `src/datastore/dynamodb.rs` implementing `DataStore` as a thin adapter over existing `AwsDynamoClient`
    - Define `DynamoDataStore` struct holding the DynamoDB `Client` and table names (billets, policies, keys)
    - Implement `new(config: &DynamoDbConfig, sdk_config: &aws_config::SdkConfig)` constructor
    - Map `BilletRecord` ↔ DynamoDB `AttributeValue` items (same schema as existing `AwsDynamoClient`)
    - Map `PolicyRecord` ↔ DynamoDB items (composite key: `billet_name` PK + `policy_id` SK)
    - Implement `delete_billet_cascade` using Query + BatchWriteItem in batches of 25
    - Implement ephemeral key operations using a dedicated keys table (`{prefix}-keys` with `purpose` PK, `key_id` SK)
    - Map `DynamoError` variants to `DataStoreError` variants
    - Reuse helper functions (`get_string`, `get_string_list`, `get_string_set`, `map_sdk_error`) from existing `src/dynamo/mod.rs`
    - _Requirements: 1.2, 1.3, 1.5, 1.6_

  - [ ]* 5.2 Write unit tests for DynamoDB DataStore adapter
    - Test AttributeValue mapping for billets and policies
    - Test error mapping from DynamoDB errors to DataStoreError
    - _Requirements: 1.2, 1.3_

- [ ] 6. Implement Firestore DataStore
  - [x] 6.1 Add `firestore` crate dependency to Cargo.toml
    - Add `firestore = "0.44"` (or latest) to `[dependencies]` with appropriate features
    - _Requirements: 2.1_

  - [x] 6.2 Create `src/datastore/firestore.rs` implementing `DataStore` for Google Cloud Firestore
    - Define `FirestoreDataStore` struct holding Firestore client, project, and collection prefix
    - Implement `new(config: &FirestoreConfig)` constructor
    - Use flat collections: `{prefix}-billets` (keyed by name), `{prefix}-policies` (keyed by `{billet_name}__{policy_id}`)
    - Implement `get_policy` by constructing document ID as `format!("{}__{}", billet_name, policy_id)`
    - Implement `list_policies_for_billet` using `where("billet_name", "==", name)` query
    - Implement `delete_billet_cascade` using query + batched deletes (max 500 per Firestore batch)
    - Use server timestamps via `FieldValue::server_timestamp()` for created_at/updated_at
    - Implement ephemeral key operations using `{prefix}-keys` collection
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [ ]* 6.3 Write unit tests for Firestore DataStore (with mocked Firestore client)
    - Test document ID construction (`billet_name__policy_id` separator)
    - Test query construction for list_policies_for_billet
    - _Requirements: 2.1, 2.2_

- [ ] 7. Define KeyManager trait and error types
  - [x] 7.1 Create `src/keymanager/mod.rs` with `KeyError` enum, `KeyHealth` enum, and `KeyManager` async trait
    - Define `KeyError` with `KeyUnavailable`, `SigningFailed`, `KmsUnavailable` variants
    - Define `KeyHealth` with `Healthy`, `Degraded { reason }`, `Unhealthy { reason }` variants
    - Define `#[async_trait] pub trait KeyManager: Send + Sync` with methods: encoding_key, header, jwks, key_id, algorithm, health, maybe_rotate
    - Register the module in `src/lib.rs`
    - _Requirements: 4.1, 4.4_

  - [x] 7.2 Create `SigningManagerAdapter` that wraps `Arc<dyn KeyManager>` and implements the existing `SigningManager` trait
    - Delegate `encoding_key()`, `header()`, `jwks()`, `key_id()` to the inner KeyManager
    - This maintains backward compatibility with code that expects `SigningManager`
    - _Requirements: 7.2, 7.3_

- [ ] 8. Implement Memory KeyManager (wrapping existing StaticKeyManager)
  - [x] 8.1 Create `src/keymanager/memory.rs` implementing `KeyManager` for in-memory static keys
    - Define `MemoryKeyManager` struct wrapping `StaticKeyManager`
    - Implement `new(config: &MemorySigningConfig)` loading PEM from key_path
    - Delegate `encoding_key()`, `header()`, `jwks()`, `key_id()` to inner `StaticKeyManager`
    - Implement `algorithm()` returning `Algorithm::ES256`
    - Implement `health()` always returning `KeyHealth::Healthy`
    - Implement `maybe_rotate()` as a no-op
    - _Requirements: 5.1, 5.2, 5.3_

  - [ ]* 8.2 Write property test for KeyManager signing round-trip (Property 6)
    - **Property 6: KeyManager Signing Round-Trip**
    - Generate arbitrary payloads, sign with MemoryKeyManager's encoding_key, verify signature against public key extracted from jwks()
    - Assert kid in header matches a kid present in JWKS response
    - **Validates: Requirements 4.2, 5.1, 6.1**

  - [ ]* 8.3 Write property test for key ID determinism (Property 8)
    - **Property 8: Key ID Determinism**
    - Generate random EC P-256 key pairs, compute key ID (base64url(SHA-256(JWK Thumbprint))) twice from same key material, assert equality
    - **Validates: Requirements 6.8**

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Implement KMS-Delegated KeyManager
  - [x] 10.1 Create `src/keymanager/kms_client.rs` with the `KmsClient` async trait
    - Define `#[async_trait] pub trait KmsClient: Send + Sync` with `sign(data: &[u8]) -> Result<Vec<u8>, KeyError>` and `verify(data: &[u8], signature: &[u8]) -> Result<bool, KeyError>`
    - Create `AwsKmsClient` struct implementing `KmsClient` using `aws-sdk-kms`
    - Create `GcpKmsClient` struct (placeholder/stub for initial implementation) implementing `KmsClient`
    - _Requirements: 6.1, 6.10_

  - [x] 10.2 Create `src/keymanager/kms_delegated.rs` implementing `KeyManager` for KMS-delegated ephemeral keys
    - Define `KmsDelegatedKeyManager` struct with fields: active_key (RwLock<EphemeralKeyState>), previous_keys (RwLock<Vec<EphemeralKeyState>>), kms_client, data_store, config, purpose
    - Define `EphemeralKeyState` struct with: encoding_key, header, jwk, key_id, created_at, expires_at
    - Implement `new(config, kms_client, data_store, purpose)` that loads existing ephemeral keys from DataStore or generates initial key
    - Implement `maybe_rotate()`: check if rotation is due, generate new EC P-256 key pair via ring, compute kid per RFC 7638, call kms_client.sign(), persist EphemeralKeyRecord to DataStore, move current to previous, set new as active
    - Implement `jwks()`: combine active_key.jwk + previous_keys where expires_at > now
    - Implement `health()`: return Degraded if key age > rotation_interval × 2, Healthy otherwise
    - On KMS failure during rotation: log warning, keep current key, set health to Degraded
    - Implement cleanup of expired keys from previous_keys and DataStore
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.11, 6.12_

  - [ ]* 10.3 Write property test for JWKS key lifecycle (Property 7)
    - **Property 7: JWKS Key Lifecycle**
    - Use `tokio::time::pause()` to simulate time advancement
    - Configure KmsDelegatedKeyManager with short rotation_interval and key_overlap
    - Trigger rotation, verify JWKS contains both keys during overlap window, only new key after overlap expires
    - **Validates: Requirements 6.3, 6.4, 6.5**

  - [ ]* 10.4 Write property test for KMS fault tolerance (Property 9)
    - **Property 9: KMS Fault Tolerance**
    - Mock KmsClient to return errors during maybe_rotate()
    - Verify active signing key remains unchanged, encoding_key() still returns a usable key, health() reports Degraded
    - **Validates: Requirements 6.12**

- [ ] 11. Implement DataStore factory and KeyManager factory
  - [x] 11.1 Create `src/datastore/factory.rs` with a `build_datastore(config: &DataStoreConfig) -> Result<Arc<dyn DataStore>, ...>` function
    - Match on `config.backend` to instantiate the correct implementation
    - For `Local`: use `config.local` or default path
    - For `Dynamodb`: require `config.dynamodb` section, build AWS SDK config
    - For `Firestore`: require `config.firestore` section
    - _Requirements: 1.4_

  - [x] 11.2 Create `src/keymanager/factory.rs` with a `build_key_manager(config: &SigningBackendConfig, data_store: Arc<dyn DataStore>) -> Result<Arc<dyn KeyManager>, ...>` function
    - Match on `config.backend` to instantiate the correct implementation
    - For `Memory`: use `config.memory` section
    - For `KmsDelegated`: use `config.kms_delegated` section, build KmsClient from aws_kms or gcp_kms sub-config, pass data_store
    - _Requirements: 4.3_

- [ ] 12. Integration wiring — update bootstrap, AppState, and PolicySyncService
  - [x] 12.1 Update `PolicySyncService` to accept `Arc<dyn DataStore>` instead of `Arc<dyn DynamoClient>`
    - Change constructor parameter from `dynamo_client: Arc<dyn DynamoClient>` to `data_store: Arc<dyn DataStore>`
    - Replace `scan_all_policies()` calls with `data_store.list_all_policies()`
    - Replace `list_billet_metadata()` calls with `data_store.list_billets()`
    - Update internal field name and all references
    - Update test mocks to use `MockDataStore` instead of `MockDynamoClient`
    - _Requirements: 7.1, 7.3_

  - [x] 12.2 Update `bootstrap_system_billets` to accept `&dyn DataStore` instead of `&dyn DynamoClient`
    - Change parameter type
    - Replace `get_billet_metadata` with `data_store.get_billet(name)`
    - Replace `put_billet_metadata` with `data_store.create_billet(record)`
    - Update tests to use `MockDataStore`
    - _Requirements: 7.1_

  - [x] 12.3 Update `AppState` and `main.rs` to use the new factories and trait objects
    - Replace `dynamo_client: Arc<dyn DynamoClient>` with `data_store: Arc<dyn DataStore>` in AppState
    - Add `signing_key_manager: Arc<dyn KeyManager>` to AppState for health checks
    - Keep `signing_manager: Arc<dyn SigningManager>` backed by `SigningManagerAdapter`
    - Update `main.rs` startup: load config → call `build_datastore()` → call `build_key_manager()` for signing and CA → construct AppState
    - Update all handlers and services that reference `dynamo_client` to use `data_store`
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 12.4 Update `BilletCrudService` and `PolicyCrudService` to accept `Arc<dyn DataStore>`
    - Replace DynamoClient dependency with DataStore
    - Map DataStore method calls (may need to adapt method signatures slightly)
    - Update unit tests
    - _Requirements: 7.1_

  - [x] 12.5 Update health endpoint to report DataStore and KeyManager health
    - Call `data_store.ping()` for DataStore health
    - Call `signing_key_manager.health()` for KeyManager health status
    - Include both in the health response JSON
    - _Requirements: 6.12_

- [x] 13. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. DataStore compliance test macro and integration tests
  - [ ]* 14.1 Create `src/datastore/tests.rs` with the `datastore_compliance_tests!` macro
    - Define macro that generates the full DataStore compliance test suite for any implementation
    - Include tests: billet CRUD round-trip, policy CRUD round-trip, cascade delete, list_all_policies, list_policies_for_billet, not-found handling, conflict on duplicate create, ping
    - Invoke macro for `LocalDataStore` using a temp directory
    - _Requirements: 1.5, 1.6, 7.4_

  - [ ]* 14.2 Write property test for DataStore behavioral equivalence (Property 2)
    - **Property 2: DataStore Behavioral Equivalence**
    - Generate random sequences of DataStore operations (creates, reads, updates, deletes, lists)
    - Apply to LocalDataStore instance, verify results match an in-memory reference model
    - **Validates: Requirements 1.3, 1.5, 7.1, 7.3**

  - [ ]* 14.3 Write integration tests for full token-exchange flow with each backend combination
    - Test PolicySyncService → DataStore → token issuance → KeyManager signing pipeline
    - Verify identical behavior regardless of which DataStore/KeyManager backend is configured
    - Use LocalDataStore + MemoryKeyManager as the baseline test combination
    - _Requirements: 7.3, 7.4_

- [x] 15. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The existing `DynamoClient` trait and `AwsDynamoClient` implementation remain in `src/dynamo/` for backward compatibility during migration; they can be deprecated after full integration wiring is complete
- The `datastore_compliance_tests!` macro enables adding future backends (e.g., Bigtable) with minimal test boilerplate
