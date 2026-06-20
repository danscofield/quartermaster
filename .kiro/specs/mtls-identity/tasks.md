# Implementation Plan: mTLS Client Certificate Identity Source

## Overview

This plan implements X.509 client certificates (SPIRE X.509-SVIDs) as an identity source for Quartermaster's token exchange and billet discovery endpoints. The implementation progresses from configuration and TLS setup through certificate extraction middleware, application-layer validation, handler integration, and audit differentiation.

## Tasks

- [ ] 1. Add TLS and mTLS configuration structures
  - [x] 1.1 Add `TlsConfig` struct to `src/config/mod.rs`
    - Add `TlsConfig` with `cert_path: String` and `key_path: String` fields
    - Add optional `tls: Option<TlsConfig>` field to `ServerConfig`
    - _Requirements: 1.1, 1.5, 1.6_

  - [x] 1.2 Add `x509_bundle_path` field to `SpireSourceConfig` in `src/config/identity.rs`
    - Add `pub x509_bundle_path: Option<String>` to `SpireSourceConfig`
    - This is distinct from `jwks_path` — it holds PEM CA certs for X.509-SVID chain validation
    - _Requirements: 2.5_

  - [ ]* 1.3 Write unit tests for TLS config parsing
    - Test `[server.tls]` deserialization with valid cert_path/key_path
    - Test absence of `[server.tls]` yields `None`
    - Test `x509_bundle_path` is optional and parsed correctly
    - _Requirements: 1.5, 1.6, 2.5_

- [ ] 2. Implement TLS acceptor setup
  - [x] 2.1 Create `src/server/tls.rs` module
    - Implement `build_tls_config(tls_config: &TlsConfig) -> Result<rustls::ServerConfig, TlsSetupError>`
    - Load server cert and private key from configured paths
    - Configure `rustls` with `WebPkiClientVerifier` set to allow unauthenticated (permissive client auth)
    - No client CA roots at TLS layer — all verification deferred to application layer
    - Add `TlsSetupError` enum for file not found, PEM parse errors
    - Register `tls` module in `src/server/mod.rs`
    - _Requirements: 1.1, 1.2, 1.4_

  - [ ]* 2.2 Write property test for TLS permissive passthrough
    - **Property 1: TLS Permissive Passthrough**
    - Verify that for any DER-encoded X.509 certificate (valid, expired, self-signed, or no cert), the TLS config builds successfully and does not reject connections
    - **Validates: Requirements 1.2, 1.3, 1.4**

  - [ ]* 2.3 Write unit tests for TLS acceptor
    - Test `build_tls_config` with valid cert/key files
    - Test error when cert file is missing
    - Test error when key file is missing
    - _Requirements: 1.1_

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement client certificate extraction middleware
  - [x] 4.1 Add `ClientCertificate` newtype and extraction middleware to `src/server/middleware.rs`
    - Define `ClientCertificate(pub Option<Vec<u8>>)` newtype (DER-encoded cert bytes)
    - Implement middleware/extractor that reads peer certificate from `tokio-rustls` connection metadata
    - Insert `ClientCertificate` into request extensions
    - When no TLS or no client cert presented, insert `ClientCertificate(None)`
    - _Requirements: 1.3, 1.4_

  - [ ]* 4.2 Write unit tests for client certificate extraction
    - Test extraction when cert is present in TLS connection
    - Test extraction yields `None` when no cert presented
    - _Requirements: 1.3, 1.4_

- [ ] 5. Implement MtlsValidator for application-layer cert validation
  - [x] 5.1 Create `src/domain/identity/mtls.rs` module
    - Implement `MtlsValidator` struct with `trust_anchors` and `trust_domain` fields
    - Implement `MtlsValidator::from_pem(ca_pem: &[u8], trust_domain: &str) -> Result<Self, MtlsError>`
    - Implement `MtlsValidator::validate(&self, cert_der: &[u8]) -> Option<SpireIdentity>`
      - Verify cert chains to a trust anchor from `x509_bundle_path`
      - Check cert is not expired
      - Extract `spiffe://` URI SAN matching configured trust domain
      - Parse environment/region from SPIFFE ID path segments
      - Set `audience` to empty vec (X.509-SVIDs don't carry audience)
    - Define `MtlsError` enum: `InvalidTrustBundle(String)`, `InvalidCertificate(String)`
    - Register module in `src/domain/identity/mod.rs`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 5.2 Write property test for SPIFFE ID extraction correctness
    - **Property 2: SPIFFE ID Extraction Correctness**
    - Generate random SPIFFE IDs, create test certs with/without valid chains and URI SANs
    - Verify `validate` returns `Some(SpireIdentity)` iff cert chains to trust anchor AND has matching `spiffe://` URI SAN
    - Verify `validate` returns `None` for invalid chains, missing SANs, wrong trust domains
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

  - [ ]* 5.3 Write unit tests for MtlsValidator
    - Test `from_pem` with valid CA PEM
    - Test `from_pem` with malformed PEM returns error
    - Test `validate` with cert that chains to trust anchor and has SPIFFE URI SAN
    - Test `validate` returns `None` for expired cert
    - Test `validate` returns `None` for cert with wrong trust domain
    - Test `validate` returns `None` for cert with no URI SAN
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Add SpireAuthSource enum and audit source type differentiation
  - [x] 7.1 Add `SpireAuthSource` enum to `src/domain/identity/mod.rs`
    - Define `SpireAuthSource { JwtSvid, MtlsCert }` enum
    - This enum indicates whether a SpireIdentity came from JWT or mTLS transport
    - _Requirements: 5.1, 5.2, 5.3_

  - [x] 7.2 Update `source_type_for_identity` in `src/domain/identity/entity.rs`
    - Modify the function signature or add a companion function that accepts a `SpireAuthSource` parameter
    - Return `"mtls-spiffe"` when source is `MtlsCert`, `"spire"` when source is `JwtSvid`
    - Ensure backward compatibility for existing call sites
    - _Requirements: 5.3_

  - [ ]* 7.3 Write property test for audit source type differentiation
    - **Property 5: Audit Source Type Differentiation**
    - Generate mTLS-sourced SpireIdentity values, verify audit event source_type is always `"mtls-spiffe"`
    - Generate JWT-sourced SpireIdentity values, verify audit event source_type is always `"spire"`
    - **Validates: Requirements 5.3**

- [ ] 8. Integrate mTLS identity into handlers
  - [x] 8.1 Update `src/handler/token.rs` with unified identity resolution
    - Make `subject_token` and `subject_token_type` optional in `TokenExchangeForm`
    - Add `Extension<ClientCertificate>` extractor to handler signature
    - Implement precedence logic: if `subject_token` present → use token dispatch (existing path); else if client cert present → validate via `MtlsValidator`; else → return 400
    - Pass `SpireAuthSource::MtlsCert` or `SpireAuthSource::JwtSvid` to audit logging
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 8.2 Update `src/handler/billets_discovery.rs` with unified identity resolution
    - Make `subject_token` and `subject_token_type` optional in `BilletDiscoveryForm`
    - Add `Extension<ClientCertificate>` extractor to handler signature
    - Apply same precedence logic as token handler
    - Pass `SpireAuthSource` to audit logging
    - _Requirements: 4.1, 4.2_

  - [ ]* 8.3 Write property test for mTLS identity fallback
    - **Property 3: mTLS Identity Fallback Produces SpireIdentity**
    - Generate valid SPIFFE IDs, mock `MtlsValidator` returning `Some(SpireIdentity)`
    - Verify handler uses mTLS identity when `subject_token` is absent
    - Verify resulting identity follows standard SPIRE resolution path
    - **Validates: Requirements 3.2, 4.1, 5.1**

  - [ ]* 8.4 Write property test for explicit token precedence
    - **Property 4: Explicit Token Precedence Over mTLS**
    - Generate pairs of (subject_token identity, mTLS identity)
    - Verify when both are present, the authenticated identity is always from subject_token
    - **Validates: Requirements 3.4, 4.2**

  - [ ]* 8.5 Write unit tests for handler precedence logic
    - Test: subject_token present with valid cert → subject_token identity used
    - Test: no subject_token, valid cert → mTLS identity used
    - Test: no subject_token, no cert → HTTP 400
    - Test: no subject_token, invalid cert → HTTP 400
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 4.1, 4.2_

- [ ] 9. Wire MtlsValidator into AppState and server startup
  - [x] 9.1 Add `mtls_validator: Option<Arc<MtlsValidator>>` to `AppState` in `src/server/mod.rs`
    - Construct `MtlsValidator` during startup only when both `[server.tls]` is configured AND `[identity.spire].x509_bundle_path` is present
    - If either is absent, set `mtls_validator = None`
    - Panic on startup if configured `x509_bundle_path` file is missing or malformed PEM
    - _Requirements: 2.5, 5.1_

  - [x] 9.2 Update server startup in `src/main.rs` to use TLS acceptor when `[server.tls]` is configured
    - Call `build_tls_config` and bind with `axum_server` TLS acceptor when TLS config present
    - Fall back to plain HTTP when `[server.tls]` is absent (existing behavior)
    - Apply client cert extraction middleware to the router
    - _Requirements: 1.1, 1.6_

  - [ ]* 9.3 Write unit tests for AppState construction logic
    - Test `mtls_validator` is `Some` when both TLS and x509_bundle_path are configured
    - Test `mtls_validator` is `None` when TLS is configured but x509_bundle_path is absent
    - Test `mtls_validator` is `None` when x509_bundle_path is present but TLS is absent
    - _Requirements: 2.5_

- [x] 10. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The implementation uses Rust with `rustls`, `webpki`, `tokio-rustls`, and `proptest`
- `MtlsValidator` is constructed only from `x509_bundle_path` (CA certs), never from `jwks_path` (JWT signing keys)
