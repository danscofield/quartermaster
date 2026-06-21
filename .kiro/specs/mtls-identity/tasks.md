# Implementation Plan: mTLS Client Certificate Identity Source

## Overview

This is a minimal fix — the vast majority of the mTLS feature already exists. The only code change needed is replacing the broken `WebPkiClientVerifier` in `src/server/tls.rs` with a custom `PermissiveClientCertVerifier` that implements the `rustls::server::danger::ClientCertVerifier` trait. All other components (middleware, MtlsValidator, handler integration, config, main.rs wiring) are already complete.

## Tasks

- [x] 1. Implement PermissiveClientCertVerifier in src/server/tls.rs
  - [x] 1.1 Add the `PermissiveClientCertVerifier` struct and implement `rustls::server::danger::ClientCertVerifier` trait
    - Create a `PermissiveClientCertVerifier` struct with a `supported_schemes` field
    - Implement `offer_client_auth()` → true
    - Implement `client_auth_mandatory()` → false
    - Implement `root_hint_subjects()` → empty slice
    - Implement `verify_client_cert()` → always Ok(ClientCertVerified::assertion())
    - Implement `verify_tls12_signature()` and `verify_tls13_signature()` using `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature` helpers
    - Implement `supported_verify_schemes()` returning default crypto provider schemes
    - _Requirements: 1.2, 1.3, 1.4_

  - [x] 1.2 Replace WebPkiClientVerifier usage in `build_tls_config()` with PermissiveClientCertVerifier
    - Remove the `WebPkiClientVerifier` import and the `empty_roots` / `WebPkiClientVerifier::builder(...)` block
    - Replace with `Arc::new(PermissiveClientCertVerifier::new())` as the client cert verifier
    - Remove unused `RootCertStore` import if no longer needed
    - _Requirements: 1.2, 1.5_

  - [ ]* 1.3 Write property test: permissive verifier never rejects (Property 1)
    - **Property 1: Permissive verifier never rejects any byte sequence**
    - Generate arbitrary `Vec<u8>` (0..2048 bytes) as fake cert DER, wrap in `CertificateDer`, call `verify_client_cert` — assert always returns `Ok`
    - Use `proptest::collection::vec(any::<u8>(), 0..2048)`
    - **Validates: Requirements 1.2**

  - [ ]* 1.4 Write unit tests for PermissiveClientCertVerifier
    - Test `offer_client_auth()` returns true
    - Test `client_auth_mandatory()` returns false
    - Test `root_hint_subjects()` returns empty
    - Test `supported_verify_schemes()` returns non-empty
    - Test `verify_client_cert` with a real self-signed cert DER returns Ok
    - Test `verify_client_cert` with empty intermediates returns Ok
    - _Requirements: 1.2, 1.3, 1.4_

- [x] 2. Checkpoint - Verify build and existing tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Add property tests for MtlsValidator correctness
  - [ ] 3.1 Write property test: SPIFFE ID extraction round-trip (Property 2)
    - **Property 2: SPIFFE ID extraction round-trip**
    - Generate valid certs with randomized SPIFFE IDs (varying environment, region segments) using `openssl` crate helpers from existing test module
    - Assert `MtlsValidator::validate()` returns `Some(SpireIdentity)` with matching `spiffe_id`, `trust_domain`, `environment`, `region`
    - **Validates: Requirements 2.2**

  - [ ] 3.2 Write property test: invalid certificates produce None (Property 3)
    - **Property 3: Invalid certificates produce None**
    - Generate certs with one randomly selected failure mode: wrong CA (untrusted), expired time, missing URI SAN, wrong trust domain
    - Assert `MtlsValidator::validate()` returns `None` for each
    - Use enum strategy to pick failure mode, then generate cert matching that mode
    - **Validates: Requirements 2.3, 2.4**

  - [ ]* 3.3 Write property test: mTLS fallback when subject_token absent (Property 4)
    - **Property 4: mTLS fallback when subject_token absent**
    - Generate arbitrary valid SPIFFE IDs with random environment/region, verify handler logic extracts mTLS identity when no subject_token is provided
    - Test via `extract_mtls_identity` helper function with mock AppState
    - **Validates: Requirements 3.2, 4.1**

  - [ ]* 3.4 Write property test: explicit token takes precedence over mTLS (Property 5)
    - **Property 5: Explicit token takes precedence over mTLS**
    - Generate pairs of (token identity, mTLS identity), verify handler precedence logic always selects the token identity when subject_token is present
    - **Validates: Requirements 3.4, 4.2**

- [ ] 4. Add integration test for build_tls_config (regression)
  - [ ]* 4.1 Write integration test verifying `build_tls_config()` does not panic
    - Create temp cert/key files, call `build_tls_config()`, assert it returns `Ok`
    - This is the regression test for the WebPkiClientVerifier panic bug
    - _Requirements: 1.5_

- [x] 5. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The core implementation change is ~30 lines in a single file (task 1.1 + 1.2)
- All handler integration, middleware, MtlsValidator, config, and main.rs wiring already exist
- Property tests use the `proptest` crate (already in dev-dependencies)
- Test cert generation uses the `openssl` crate (already in dev-dependencies)
- Checkpoints ensure incremental validation
