# Requirements Document — mTLS Client Certificate Identity Source

## Introduction

This spec adds X.509 client certificates (SPIRE X.509-SVIDs) as an identity source for token exchange. When a workload presents a valid client cert during the TLS handshake, Quartermaster extracts the SPIFFE ID from the URI SAN and uses it as the authenticated identity — no `subject_token` needed in the request body.

## Requirements

### Requirement 1: TLS Configuration with Permissive Client Cert Acceptance

#### Acceptance Criteria

1. THE server SHALL support TLS termination with configurable server cert and key
2. THE TLS listener SHALL accept client certificates but SHALL NOT verify them at the handshake layer — all connections succeed regardless of client cert presence or issuer
3. THE raw client certificate (if presented) SHALL be passed through to the application layer for handler-level validation
4. WHEN no client certificate is presented, THE TLS handshake SHALL succeed normally
5. Configuration:
   ```toml
   [server.tls]
   cert_path = "/etc/quartermaster/tls/server.crt"
   key_path = "/etc/quartermaster/tls/server.key"
   ```
6. IF `[server.tls]` is absent, THE server SHALL listen on plain HTTP (current behavior, for local dev)

### Requirement 2: Application-Layer Client Cert Validation

#### Acceptance Criteria

1. WHEN a client certificate is present on the connection, THE handler SHALL attempt to validate it against all configured identity source trust bundles (e.g., SPIRE CA trust bundle)
2. IF the cert's chain validates against a known trust bundle AND contains a `spiffe://` URI SAN, THE system SHALL extract the SPIFFE ID as the mTLS identity
3. IF the cert does not validate against any configured trust bundle, THE system SHALL ignore it — no error, no mTLS identity extracted. The handler falls through to `subject_token` in the body.
4. IF the cert validates but contains no recognized URI SAN pattern, THE system SHALL ignore it (same as unverified)
5. THE trust bundles used for client cert validation SHALL be loaded from `[identity.spire].x509_bundle_path` — a PEM file containing the CA certificates (root/intermediate) that issued the X.509-SVIDs. This is distinct from `jwks_path` which provides JWT signing keys for JWT-SVID verification.

### Requirement 3: Token Exchange with mTLS Identity

#### Acceptance Criteria

1. THE `subject_token` and `subject_token_type` fields on `POST /token` SHALL be optional (not required)
2. WHEN `subject_token` is absent AND a verified mTLS identity is present, THE system SHALL use the mTLS identity as the authenticated identity (SPIFFE ID extracted from client cert)
3. WHEN `subject_token` is absent AND no mTLS identity is present, THE system SHALL return HTTP 400: "subject_token is required when no client certificate is presented"
4. WHEN `subject_token` is present, THE system SHALL use it regardless of whether a client cert is also present (explicit token takes precedence)
5. THE mTLS-authenticated identity SHALL follow the same flow as a SPIRE JWT-SVID: selector enrichment → Cedar evaluation → billet resolution → token issuance

### Requirement 4: Billet Discovery with mTLS Identity

#### Acceptance Criteria

1. THE `POST /billets/me` endpoint SHALL also support mTLS identity — `subject_token` is optional when a client cert is present
2. Same precedence rules as `/token`: explicit token wins, mTLS is fallback

### Requirement 5: New AuthenticatedIdentity Variant

#### Acceptance Criteria

1. THE system SHALL treat mTLS-authenticated identities as `AuthenticatedIdentity::Spire(SpireIdentity)` — same variant as JWT-SVID, same entity construction, same Cedar evaluation
2. THE only difference is the source of the SPIFFE ID: TLS layer (URI SAN) vs application layer (JWT `sub` claim)
3. THE audit log `source_type` for mTLS-authenticated requests SHALL be `"mtls-spiffe"` (distinct from `"spire"` for JWT-SVIDs)

### Requirement 6: OpenAPI Documentation

#### Acceptance Criteria

1. THE OpenAPI spec SHALL document `subject_token` and `subject_token_type` as optional fields
2. THE OpenAPI spec SHALL include a `mutualTLS` security scheme
3. THE endpoint descriptions SHALL note: "subject_token is required unless a SPIRE X.509-SVID is presented as a TLS client certificate"
