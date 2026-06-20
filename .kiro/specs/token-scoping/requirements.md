# Requirements Document — Token Scoping & Billet Discovery

## Introduction

This spec adds two capabilities: (1) requesting a subset of billets when exchanging a token, so that issued JWTs contain only what's needed (least privilege), and (2) a discovery endpoint that tells the caller which billets they're entitled to, enabling clients to make informed scoping decisions.

## Requirements

### Requirement 1: Scoped Token Exchange

**User Story:** As a workload or human, I want to request only the billets I need in my token, so that my JWT is small, least-privileged, and doesn't exceed cloud provider token size limits.

#### Acceptance Criteria

1. THE `POST /token` endpoint SHALL accept an optional `billets` form parameter containing a comma-separated list of billet names
2. WHEN `billets` is present, THE system SHALL resolve the full set of billets the caller is entitled to (via Cedar evaluation + implicit mapping), then intersect with the requested set
3. IF all requested billets are in the entitled set, THE issued JWT SHALL contain only the requested billets (not the full entitled set)
4. IF any requested billet is NOT in the entitled set, THE system SHALL return HTTP 403 with an error indicating which billets were denied
5. WHEN `billets` is absent, THE system SHALL issue a JWT containing all entitled billets (current behavior, unchanged)
6. THE `billets` parameter SHALL NOT allow requesting billets the caller is not entitled to — it can only narrow, never expand

### Requirement 2: Billet Discovery Endpoint

**User Story:** As a client library or sidecar, I want to discover which billets I'm entitled to before requesting a scoped token, so that I can make informed decisions about what to request.

#### Acceptance Criteria

1. THE system SHALL expose a `POST /billets/me` endpoint
2. THE request SHALL accept the same `subject_token` and `subject_token_type` parameters as `/token` (proving identity)
3. THE system SHALL validate the upstream token, resolve all entitled billets (Cedar + implicit), and return them without issuing a JWT
4. THE response SHALL be HTTP 200 with a JSON body:
   ```json
   {
     "billets": ["billing-writer", "audit-reader", "okta-group:billing-ops"],
     "implicit_billets": ["okta-group:billing-ops"],
     "cedar_billets": ["billing-writer", "audit-reader"]
   }
   ```
5. THE endpoint SHALL NOT issue a token or certificate — it is read-only discovery
6. IF the caller has no entitled billets, return HTTP 200 with empty arrays (not 403 — discovery shouldn't fail)
7. THE endpoint SHALL be rate-limited per identity (same rate limiter as `/token`)

### Requirement 3: Certificate Scoping

**User Story:** As a workload requesting a certificate, I want the cert to contain only the billets I specified, matching the JWT scope.

#### Acceptance Criteria

1. WHEN both `billets` and `csr` parameters are present on `POST /token`, THE issued certificate SHALL contain URI SANs only for the requested (scoped) billets, not all entitled billets
2. THE certificate billets SHALL always match the JWT billets — cross-credential consistency is maintained regardless of scoping
