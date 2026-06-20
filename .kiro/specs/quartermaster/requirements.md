# Requirements Document

## Introduction

Quartermaster is a workload identity federation broker that sits between platform-native attestation (SPIRE) and cloud provider IAM systems. It introduces billets — an intermediate authorization abstraction that decouples workload identity from cloud role assignment. Workloads prove identity via SPIRE SVIDs, Quartermaster evaluates Cedar policies locally (via the `cedar-policy` Rust crate, with policies stored in DynamoDB) to determine billet holdings, and issues signed JWTs and X.509 certificates for cross-cloud role assumption and mTLS respectively.

This requirements document covers the prototype scope: token exchange, OIDC discovery, CA trust bundle, certificate issuance (local CA), in-memory cache, static signing key, and DynamoDB-backed policy/billet storage with local Cedar evaluation.

## Glossary

- **Quartermaster**: The workload identity federation broker system that resolves billets and issues credentials
- **Billet**: A named authorization role within Quartermaster's domain, representing a position a workload can hold
- **SVID**: A SPIFFE Verifiable Identity Document — a JWT issued by SPIRE attesting workload identity
- **SPIFFE_ID**: A URI identifying a workload, e.g. `spiffe://example.com/ns/finance/workload/payments`
- **Token_Exchange_Endpoint**: The HTTP endpoint accepting SVIDs and returning Quartermaster credentials
- **Billet_Resolver**: The component that evaluates Cedar policies locally (via the cedar-policy crate) to determine workload billet holdings
- **Certificate_Authority**: The component that issues short-lived X.509 certificates embedding billets
- **OIDC_Provider**: The component serving OpenID Connect discovery and JWKS endpoints
- **Trust_Bundle_Endpoint**: The endpoint serving the Quartermaster CA certificate chain
- **Signing_Key_Manager**: The component managing JWT signing keys and JWKS publication
- **Cache**: An abstract interface for storing and retrieving billet resolution results, keyed by SPIFFE ID and audience; implementations include in-memory (local development) and distributed stores such as Redis (fleet deployment)
- **Cache_Backend**: A concrete implementation of the Cache interface providing storage semantics (e.g., memory, Redis, Memcached)
- **Selector**: A SPIRE workload selector — a key:value attestation attribute attached to a registration entry (e.g., `k8s:ns:finance`, `k8s:sa:payments-sa`, `k8s:pod-label:project:payments`)
- **SPIRE_Server_API**: The SPIRE Server's registration API used by Quartermaster to look up registration entries and their selectors
- **DynamoDB**: AWS DynamoDB — the backing store for Cedar policies (quartermaster-policies table) and billet metadata (quartermaster-billets table)
- **DynamoClient**: The trait abstracting DynamoDB operations for policy CRUD and billet metadata CRUD
- **PolicySyncService**: The background task that scans the quartermaster-policies DynamoDB table, parses statements into a cedar_policy::PolicySet, extracts known billet names, and atomically swaps the active PolicySet on a configurable interval
- **PolicySet**: An in-memory cedar_policy::PolicySet holding all parsed Cedar policies, refreshed by the PolicySyncService
- **Cedar_Engine**: The `cedar-policy` Rust crate used for in-process Cedar policy evaluation — no external service dependency on the authorization hot path
- **Cedar_Policy**: A policy written in Cedar language, stored in the quartermaster-policies DynamoDB table and synced to the in-memory PolicySet for evaluation
- **CSR**: Certificate Signing Request — a PKCS#10 message containing a public key for certificate issuance
- **JWKS**: JSON Web Key Set — the set of public keys used to verify Quartermaster JWTs
- **Trust_Domain**: The SPIFFE trust domain that Quartermaster accepts SVIDs from
- **Control_Plane**: The administrative API surface of Quartermaster that allows managing billets and Cedar policies, accessible at `/admin/*` paths
- **Billets_Table**: The quartermaster-billets DynamoDB table that stores billet metadata (description, associated_aws_roles, associated_gcp_sas); billet names for authorization are derived from policies in the PolicySet, not from this table
- **quartermaster-admin**: A reserved bootstrap billet with broad admin permissions; additional granular admin billets can be created at runtime
- **Control_Plane_Authenticator**: The component that validates Quartermaster JWTs on Control_Plane requests and evaluates admin authorization via local cedar-policy evaluation — the caller's billets become principals, the admin action + target resource are evaluated against Cedar policies
- **Workload**: The base Cedar entity type representing any workload. Never persisted — constructed ephemerally at authorization-time from SVID claims and SPIRE selectors. Has common attributes: spiffe_id, trust_domain, environment, region, selectors
- **K8sWorkload**: A Cedar entity subtype of Workload for workloads attested by SPIRE's Kubernetes workload attestor. Adds: namespace, service_account, pod_labels, container_name, node_name
- **Ec2Workload**: A Cedar entity subtype of Workload for workloads attested by SPIRE's AWS IID attestor. Adds: instance_id, account_id, ami_id, instance_tags, security_groups
- **GcpWorkload**: A Cedar entity subtype of Workload for workloads attested by SPIRE's GCP IIT attestor. Adds: project_id, zone, service_account_email, instance_name
- **Policy**: A Cedar entity type representing a policy in the quartermaster-policies DynamoDB table, with attributes: id, description

## Requirements

### Requirement 1: SVID Validation

**User Story:** As a platform operator, I want Quartermaster to validate incoming SPIRE SVIDs before issuing credentials, so that only authentically attested workloads can obtain billets.

#### Acceptance Criteria

1. WHEN a token exchange request is received, THE Token_Exchange_Endpoint SHALL verify the SVID signature against the SPIRE trust bundle
2. WHEN a token exchange request is received, THE Token_Exchange_Endpoint SHALL verify that the SVID has not expired
3. WHEN a token exchange request is received, THE Token_Exchange_Endpoint SHALL verify that the SVID issuer matches a configured Trust_Domain
4. WHEN a token exchange request is received, THE Token_Exchange_Endpoint SHALL verify that the SVID audience includes Quartermaster's issuer identifier
5. IF the SVID signature verification fails, THEN THE Token_Exchange_Endpoint SHALL return HTTP 401 with an error description indicating signature validation failure
6. IF the SVID has expired, THEN THE Token_Exchange_Endpoint SHALL return HTTP 401 with an error description indicating token expiry
7. IF the SVID issuer does not match a configured Trust_Domain, THEN THE Token_Exchange_Endpoint SHALL return HTTP 401 with an error description indicating unknown trust domain

### Requirement 2: Token Exchange Request Handling

**User Story:** As a workload developer, I want to exchange my SPIRE SVID for Quartermaster credentials using the RFC 8693 token exchange grant, so that I can obtain billets for cross-cloud access.

#### Acceptance Criteria

1. THE Token_Exchange_Endpoint SHALL accept POST requests at the `/token` path with content type `application/x-www-form-urlencoded`
2. WHEN a valid token exchange request is received, THE Token_Exchange_Endpoint SHALL require the `grant_type` parameter with value `urn:ietf:params:oauth:grant-type:token-exchange`
3. WHEN a valid token exchange request is received, THE Token_Exchange_Endpoint SHALL require the `subject_token` parameter containing the JWT-SVID
4. WHEN a valid token exchange request is received, THE Token_Exchange_Endpoint SHALL require the `subject_token_type` parameter with value `urn:ietf:params:oauth:token-type:jwt`
5. WHEN a valid token exchange request is received, THE Token_Exchange_Endpoint SHALL require the `audience` parameter specifying the target cloud STS endpoint
6. WHEN a valid token exchange request includes a `csr` parameter, THE Token_Exchange_Endpoint SHALL treat the value as a base64-encoded PKCS#10 CSR
7. IF a required parameter is missing or malformed, THEN THE Token_Exchange_Endpoint SHALL return HTTP 400 with a descriptive error message
8. IF the `grant_type` parameter does not match the token-exchange grant type, THEN THE Token_Exchange_Endpoint SHALL return HTTP 400

### Requirement 3: Billet Resolution

**User Story:** As a platform operator, I want Quartermaster to evaluate Cedar policies locally (using the cedar-policy crate with policies synced from DynamoDB) to determine which billets a workload holds, so that billet assignment is governed by centralized, auditable policy without per-request network calls.

#### Acceptance Criteria

1. WHEN a valid SVID has been authenticated, THE Billet_Resolver SHALL construct an ephemeral Workload entity (with appropriate platform subtype — K8sWorkload, Ec2Workload, or GcpWorkload — based on SPIRE selectors) and evaluate locally via the cedar-policy crate with that entity as principal, `assumeBillet` as action, and all known billet entity IDs (derived from the PolicySet by the PolicySyncService) as resources
2. WHEN the local Cedar evaluation returns authorization decisions, THE Billet_Resolver SHALL collect the set of billets for which the decision is "Allow"
3. IF the local evaluation returns all decisions as "Deny", THEN THE Token_Exchange_Endpoint SHALL return HTTP 403 indicating the workload holds no billets
4. IF the local PolicySet has not been initialized (DynamoDB sync failure on startup) and no cached result exists, THEN THE Token_Exchange_Endpoint SHALL return HTTP 503 indicating service unavailability
5. THE Billet_Resolver SHALL populate the ephemeral Workload entity's common attributes (spiffe_id, trust_domain, environment, region, selectors) from SVID claims and SPIRE selectors
6. THE Billet_Resolver SHALL include request context (environment, region, request_time, source_cloud, selectors) in the authorization request as a CommonContext
7. THE Billet_Resolver SHALL include workload selectors retrieved from the SPIRE_Server_API both as entity attributes on the Workload and in the authorization request context

### Requirement 4: JWT Issuance

**User Story:** As a workload developer, I want Quartermaster to issue a signed JWT containing my resolved billets, so that I can use it to assume cloud IAM roles via OIDC federation.

#### Acceptance Criteria

1. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT containing the `iss` claim set to Quartermaster's configured issuer URL
2. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT containing the `sub` claim set to the workload's SPIFFE_ID
3. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT containing the `aud` claim set to the audience parameter from the request
4. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT containing the `billets` claim as an array of resolved billet names
5. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT with `iat` and `exp` claims bounding the token lifetime to the configured TTL (default 300 seconds)
6. WHEN billet resolution succeeds, THE Token_Exchange_Endpoint SHALL issue a JWT with a cryptographically random `jti` claim for unique identification
7. THE Token_Exchange_Endpoint SHALL sign the JWT using the configured signing algorithm (ES256 for prototype)
8. THE Token_Exchange_Endpoint SHALL return the JWT in a JSON response body with `access_token`, `issued_token_type`, `token_type`, and `expires_in` fields

### Requirement 5: Certificate Issuance

**User Story:** As a workload developer, I want Quartermaster to issue a short-lived X.509 certificate embedding my billets, so that I can use it for billet-gated mTLS with peer services.

#### Acceptance Criteria

1. WHEN a token exchange request includes a valid CSR, THE Certificate_Authority SHALL issue an X.509 certificate using the public key from the CSR
2. WHEN issuing a certificate, THE Certificate_Authority SHALL set the Subject CN to the workload's SPIFFE_ID
3. WHEN issuing a certificate, THE Certificate_Authority SHALL include the workload's SPIFFE_ID as a URI SAN
4. WHEN issuing a certificate, THE Certificate_Authority SHALL include one `qm-billet://` URI SAN per resolved billet
5. WHEN issuing a certificate, THE Certificate_Authority SHALL set the certificate validity period equal to the configured token TTL (default 300 seconds)
6. WHEN issuing a certificate, THE Certificate_Authority SHALL set Key Usage to Digital Signature and Key Encipherment
7. WHEN issuing a certificate, THE Certificate_Authority SHALL set Extended Key Usage to TLS Client Authentication and TLS Server Authentication
8. WHEN issuing a certificate, THE Certificate_Authority SHALL generate a cryptographically random serial number
9. THE Certificate_Authority SHALL ignore the Subject and SANs in the submitted CSR and populate them exclusively from the authenticated SPIFFE_ID and resolved billets
10. WHEN issuing a certificate, THE Token_Exchange_Endpoint SHALL return the PEM-encoded certificate chain (leaf + intermediate CA) in the `certificate_chain` response field
11. WHEN a token exchange request does not include a CSR, THE Token_Exchange_Endpoint SHALL omit the `certificate_chain` field from the response

### Requirement 6: OIDC Discovery

**User Story:** As a cloud provider administrator, I want Quartermaster to serve standard OIDC discovery endpoints, so that cloud IAM systems can verify Quartermaster tokens.

#### Acceptance Criteria

1. THE OIDC_Provider SHALL serve a JSON document at `GET /.well-known/openid-configuration`
2. THE OIDC_Provider SHALL include the `issuer` field matching Quartermaster's configured issuer URL in the discovery document
3. THE OIDC_Provider SHALL include the `jwks_uri` field pointing to the JWKS endpoint in the discovery document
4. THE OIDC_Provider SHALL include `response_types_supported` containing `id_token` in the discovery document
5. THE OIDC_Provider SHALL include `subject_types_supported` containing `public` in the discovery document
6. THE OIDC_Provider SHALL include `id_token_signing_alg_values_supported` containing the configured signing algorithm in the discovery document
7. THE OIDC_Provider SHALL include `claims_supported` listing `sub`, `iss`, `aud`, `exp`, `iat`, `billets`, and `jti` in the discovery document

### Requirement 7: JWKS Endpoint

**User Story:** As a cloud provider's STS service, I want to retrieve Quartermaster's public signing keys, so that I can verify the signatures on Quartermaster JWTs.

#### Acceptance Criteria

1. THE Signing_Key_Manager SHALL serve a JSON Web Key Set at `GET /jwks.json`
2. THE Signing_Key_Manager SHALL include the current signing key's public component in the JWKS response
3. THE Signing_Key_Manager SHALL include the key ID (`kid`) in each JWK entry matching the `kid` header in issued JWTs
4. THE Signing_Key_Manager SHALL include the key algorithm (`alg`) in each JWK entry matching the configured signing algorithm

### Requirement 8: CA Trust Bundle Endpoint

**User Story:** As a workload developer, I want to retrieve Quartermaster's CA certificate chain, so that I can configure my TLS verifier to trust peer certificates issued by Quartermaster.

#### Acceptance Criteria

1. THE Trust_Bundle_Endpoint SHALL serve the CA certificate chain in PEM format at `GET /ca/chain.pem`
2. THE Trust_Bundle_Endpoint SHALL return the Quartermaster intermediate CA certificate followed by any parent certificates in the chain
3. THE Trust_Bundle_Endpoint SHALL set the Content-Type header to `application/x-pem-file`

### Requirement 9: Billet Resolution Cache

**User Story:** As a platform operator, I want Quartermaster to access billet resolution cache through an abstract interface with pluggable backends, so that the system can scale from local development (in-memory) to fleet deployments (distributed store) without code changes.

#### Acceptance Criteria

1. THE Cache SHALL define an abstract interface with operations for storing, retrieving, and expiring billet resolution entries
2. THE Cache SHALL accept a configured Cache_Backend implementation at startup without requiring changes to the Token_Exchange_Endpoint or Billet_Resolver
3. WHEN billet resolution succeeds, THE Cache SHALL store the result keyed by the combination of SPIFFE_ID and audience using the configured Cache_Backend
4. WHEN a subsequent token exchange request matches a cached entry, THE Token_Exchange_Endpoint SHALL use the cached billet resolution result instead of re-evaluating Cedar policies
5. THE Cache SHALL expire entries after the configured TTL (matching the token TTL, default 300 seconds) regardless of which Cache_Backend is active
6. THE Cache SHALL NOT serve entries beyond the configured TTL
7. WHERE the in-memory Cache_Backend is configured, THE Cache SHALL store entries in process-local memory (suitable for single-instance and development use)
8. WHERE a distributed Cache_Backend is configured, THE Cache SHALL store entries in the external store (e.g., Redis) accessible to all Quartermaster instances in the fleet
9. WHERE a distributed Cache_Backend is configured, THE Cache SHALL tolerate temporary unavailability of the backing store by falling through to local Cedar policy evaluation for billet resolution
10. FOR ALL Cache_Backend implementations, storing a value and then retrieving it by the same key before TTL expiry SHALL return the original value (round-trip property)

### Requirement 10: Audience Binding

**User Story:** As a security engineer, I want Quartermaster tokens to be scoped to a single audience, so that a token intended for one cloud provider cannot be replayed against another.

#### Acceptance Criteria

1. THE Token_Exchange_Endpoint SHALL include exactly one value in the JWT `aud` claim matching the requested audience
2. THE Token_Exchange_Endpoint SHALL NOT issue tokens with wildcard audience claims
3. THE Token_Exchange_Endpoint SHALL NOT issue tokens with multiple audience values

### Requirement 11: Rate Limiting

**User Story:** As a platform operator, I want Quartermaster to rate-limit token exchange requests per workload, so that a compromised workload cannot overwhelm the system.

#### Acceptance Criteria

1. THE Token_Exchange_Endpoint SHALL enforce a configurable maximum number of requests per SPIFFE_ID per minute (default: 10)
2. IF a workload exceeds the configured rate limit, THEN THE Token_Exchange_Endpoint SHALL return HTTP 429 with a Retry-After header

### Requirement 12: Audit Logging

**User Story:** As a security auditor, I want all token issuance events to be logged with relevant context, so that I can trace credential usage and investigate incidents.

#### Acceptance Criteria

1. WHEN a token is issued, THE Token_Exchange_Endpoint SHALL log the workload's SPIFFE_ID, resolved billets, target audience, issuance timestamp, and JTI
2. WHEN a token exchange request fails, THE Token_Exchange_Endpoint SHALL log the workload's SPIFFE_ID (if available), failure reason, and timestamp
3. THE Token_Exchange_Endpoint SHALL produce structured log entries (JSON format)

### Requirement 13: Health Check

**User Story:** As a platform operator, I want a health check endpoint, so that load balancers and orchestrators can determine if a Quartermaster instance is ready to serve traffic.

#### Acceptance Criteria

1. THE Token_Exchange_Endpoint SHALL serve a health check at `GET /healthz`
2. WHEN the SPIRE trust bundle is loaded and the PolicySet has been loaded (first DynamoDB sync succeeded), THE Token_Exchange_Endpoint SHALL return HTTP 200 from the health check endpoint
3. IF the SPIRE trust bundle is not loaded, THEN THE Token_Exchange_Endpoint SHALL return HTTP 503 from the health check endpoint
4. IF the PolicySet has not been loaded (first DynamoDB sync has not succeeded), THEN THE Token_Exchange_Endpoint SHALL return HTTP 503 from the health check endpoint

### Requirement 14: Token Response Format

**User Story:** As a workload developer, I want the token exchange response to follow a predictable structure, so that client libraries can parse Quartermaster responses reliably.

#### Acceptance Criteria

1. WHEN a token exchange succeeds, THE Token_Exchange_Endpoint SHALL return HTTP 200 with Content-Type `application/json`
2. WHEN a token exchange succeeds, THE Token_Exchange_Endpoint SHALL include `access_token` containing the signed JWT in the response
3. WHEN a token exchange succeeds, THE Token_Exchange_Endpoint SHALL include `issued_token_type` set to `urn:ietf:params:oauth:token-type:jwt` in the response
4. WHEN a token exchange succeeds, THE Token_Exchange_Endpoint SHALL include `token_type` set to `Bearer` in the response
5. WHEN a token exchange succeeds, THE Token_Exchange_Endpoint SHALL include `expires_in` set to the token TTL in seconds in the response
6. FOR ALL successful token exchange responses, parsing the `access_token` as a JWT and re-encoding it SHALL produce a semantically equivalent token (round-trip property)

### Requirement 15: CSR Validation

**User Story:** As a security engineer, I want Quartermaster to validate and constrain CSR processing, so that workloads cannot inject unauthorized identity claims via the CSR.

#### Acceptance Criteria

1. WHEN a CSR is submitted, THE Certificate_Authority SHALL parse the CSR as a valid PKCS#10 structure
2. WHEN a CSR is submitted, THE Certificate_Authority SHALL verify the CSR self-signature to confirm possession of the private key
3. THE Certificate_Authority SHALL use only the public key from the CSR for certificate issuance
4. THE Certificate_Authority SHALL discard any Subject, SANs, or extensions present in the CSR
5. IF the CSR is malformed or has an invalid self-signature, THEN THE Token_Exchange_Endpoint SHALL return HTTP 400 with a descriptive error

### Requirement 16: JWT Signature Verification (Round-Trip)

**User Story:** As a relying party, I want to verify Quartermaster JWTs using the published JWKS, so that I can trust the token contents.

#### Acceptance Criteria

1. FOR ALL JWTs issued by the Token_Exchange_Endpoint, verifying the signature using the corresponding public key from the JWKS endpoint SHALL succeed
2. THE Token_Exchange_Endpoint SHALL include a `kid` header in issued JWTs matching the key ID in the JWKS response
3. FOR ALL issued JWTs, the `iss` claim SHALL match the `issuer` field in the OIDC discovery document

### Requirement 17: Certificate Chain Verification (Round-Trip)

**User Story:** As a peer workload, I want to verify Quartermaster-issued certificates against the published CA trust bundle, so that I can establish trusted mTLS connections.

#### Acceptance Criteria

1. FOR ALL certificates issued by the Certificate_Authority, verifying the certificate chain against the trust bundle from the Trust_Bundle_Endpoint SHALL succeed
2. FOR ALL issued certificates, the SPIFFE_ID in the URI SAN SHALL match the `sub` claim in the corresponding JWT
3. FOR ALL issued certificates, the set of billets encoded in `qm-billet://` URI SANs SHALL match the `billets` claim in the corresponding JWT


### Requirement 18: Control Plane Authentication

**User Story:** As a platform operator, I want all control plane operations to be authorized via local Cedar policy evaluation where the caller's billets are principals, so that administrative access is governed by the same Cedar policy engine the system manages (dogfooding) and can be made arbitrarily granular at runtime.

#### Acceptance Criteria

1. WHEN a request is received at any `/admin/*` path, THE Control_Plane_Authenticator SHALL require a valid Quartermaster JWT in the `Authorization` header using the `Bearer` scheme
2. WHEN a request is received at any `/admin/*` path, THE Control_Plane_Authenticator SHALL verify the JWT signature against Quartermaster's own JWKS
3. WHEN a request is received at any `/admin/*` path, THE Control_Plane_Authenticator SHALL extract the billets from the JWT and evaluate a local Cedar authorization request where each billet becomes a `Quartermaster::Billet` principal, the admin action (e.g., `createBillet`, `deleteBillet`, `createPolicy`, `updatePolicy`, `deletePolicy`) is the action, and the target resource is the resource
4. IF the local evaluation returns "Allow" for at least one of the caller's billets, THEN THE Control_Plane_Authenticator SHALL permit the request
5. IF the `Authorization` header is missing from a Control_Plane request, THEN THE Control_Plane_Authenticator SHALL return HTTP 401 with an error description indicating missing credentials
6. IF the JWT signature verification fails on a Control_Plane request, THEN THE Control_Plane_Authenticator SHALL return HTTP 401 with an error description indicating invalid token
7. IF the JWT has expired on a Control_Plane request, THEN THE Control_Plane_Authenticator SHALL return HTTP 401 with an error description indicating token expiry
8. IF the local evaluation returns "Deny" for all of the caller's billets for the requested action and resource, THEN THE Control_Plane_Authenticator SHALL return HTTP 403 indicating insufficient privileges
9. THE bootstrap billet `quartermaster-admin` SHALL have a Cedar policy granting it all admin actions (createBillet, deleteBillet, createPolicy, updatePolicy, deletePolicy) on all resources
10. A Cedar policy SHALL exist permitting any `Quartermaster::Billet` principal to perform `readBillet` on itself (self-read policy)

### Requirement 19: Billet Management — Create

**User Story:** As a platform operator, I want to create new billet definitions via the control plane, so that I can extend the authorization model without redeploying Quartermaster.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a POST request to `/admin/billets`, THE Control_Plane SHALL create a new billet metadata record in the quartermaster-billets DynamoDB table
2. WHEN creating a billet, THE Control_Plane SHALL require a `name` field containing a non-empty string that is unique across existing billet records
3. WHEN creating a billet, THE Control_Plane SHALL accept an optional `description` field
4. WHEN a billet is created successfully, THE Control_Plane SHALL return HTTP 201 with the created billet definition in the response body
5. IF the billet name already exists in the quartermaster-billets DynamoDB table, THEN THE Control_Plane SHALL return HTTP 409 indicating a conflict
6. WHEN creating a billet, THE Control_Plane SHALL accept an optional `associated_aws_roles` field containing a list of AWS IAM role ARNs that the billet maps to
7. WHEN creating a billet, THE Control_Plane SHALL accept an optional `associated_gcp_sas` field containing a list of GCP service account emails that the billet maps to

### Requirement 20: Billet Management — List

**User Story:** As a platform operator, I want to list all registered billets via the control plane, so that I can audit and review the current authorization model.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a GET request to `/admin/billets`, THE Control_Plane SHALL return the complete list of billet records from the quartermaster-billets DynamoDB table (enriched with billet names derived from the PolicySet)
2. WHEN listing billets, THE Control_Plane SHALL return HTTP 200 with a JSON array of billet definitions
3. WHEN listing billets, THE Control_Plane SHALL include the `name` and `description` fields for each billet in the response

### Requirement 21: Billet Management — Get

**User Story:** As a platform operator, I want to retrieve a specific billet's details via the control plane, so that I can inspect its current definition.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a GET request to `/admin/billets/{name}`, THE Control_Plane SHALL return the billet metadata record matching the specified name from the quartermaster-billets DynamoDB table
2. WHEN the billet exists, THE Control_Plane SHALL return HTTP 200 with the billet's `name`, `description`, `associated_aws_roles`, and `associated_gcp_sas` in the response body
3. IF the specified billet name does not exist in the quartermaster-billets DynamoDB table, THEN THE Control_Plane SHALL return HTTP 404 indicating the billet was not found

### Requirement 22: Billet Management — Delete

**User Story:** As a platform operator, I want to delete billet definitions via the control plane, so that I can retire billets that are no longer needed.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a DELETE request to `/admin/billets/{name}`, THE Control_Plane SHALL remove the billet metadata record from the quartermaster-billets DynamoDB table
2. WHEN a billet is deleted successfully, THE Control_Plane SHALL return HTTP 204 with no response body
3. IF the specified billet name does not exist in the quartermaster-billets DynamoDB table, THEN THE Control_Plane SHALL return HTTP 404 indicating the billet was not found
4. THE Control_Plane SHALL NOT allow deletion of the `quartermaster-admin` billet

### Requirement 23: Policy Management — Create

**User Story:** As a platform operator, I want to create new Cedar policies in the quartermaster-policies DynamoDB table via the control plane, so that I can govern billet assignment through a management API.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a POST request to `/admin/policies`, THE Control_Plane SHALL create a new Cedar policy in the quartermaster-policies DynamoDB table
2. WHEN creating a policy, THE Control_Plane SHALL require a `statement` field containing a valid Cedar policy statement
3. WHEN creating a policy, THE Control_Plane SHALL accept an optional `description` field
4. WHEN a policy is created successfully, THE Control_Plane SHALL return HTTP 201 with the policy identifier and metadata in the response body
5. IF the Cedar policy statement is syntactically invalid, THEN THE Control_Plane SHALL return HTTP 400 with a descriptive error
6. WHEN creating a policy, THE Control_Plane SHALL validate the Cedar statement locally (parse with cedar_policy::PolicySet::from_str and validate against the Cedar schema) before writing to DynamoDB

### Requirement 24: Policy Management — Update

**User Story:** As a platform operator, I want to update existing Cedar policies via the control plane, so that I can modify billet assignment rules without deleting and recreating policies.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a PUT request to `/admin/policies/{policyId}`, THE Control_Plane SHALL update the specified Cedar policy in the quartermaster-policies DynamoDB table
2. WHEN updating a policy, THE Control_Plane SHALL require a `statement` field containing the new Cedar policy statement
3. WHEN a policy is updated successfully, THE Control_Plane SHALL return HTTP 200 with the updated policy metadata in the response body
4. IF the specified policy identifier does not exist in the quartermaster-policies DynamoDB table, THEN THE Control_Plane SHALL return HTTP 404 indicating the policy was not found
5. IF the updated Cedar policy statement is syntactically invalid, THEN THE Control_Plane SHALL return HTTP 400 with a descriptive error

### Requirement 25: Policy Management — Delete

**User Story:** As a platform operator, I want to delete Cedar policies from the quartermaster-policies DynamoDB table via the control plane, so that I can remove outdated or incorrect authorization rules.

#### Acceptance Criteria

1. WHEN an authenticated admin submits a DELETE request to `/admin/policies/{policyId}`, THE Control_Plane SHALL remove the specified Cedar policy from the quartermaster-policies DynamoDB table
2. WHEN a policy is deleted successfully, THE Control_Plane SHALL return HTTP 204 with no response body
3. IF the specified policy identifier does not exist in the quartermaster-policies DynamoDB table, THEN THE Control_Plane SHALL return HTTP 404 indicating the policy was not found


### Requirement 26: SPIRE Selector Enrichment

**User Story:** As a platform operator, I want Quartermaster to retrieve SPIRE selectors for a workload and pass them as context to Cedar policies, so that billet assignment can be conditioned on rich platform attestation metadata (namespace, service account, pod labels, etc.) without requiring that metadata in the SVID itself.

#### Acceptance Criteria

1. WHEN a valid SVID has been authenticated, THE Billet_Resolver SHALL query the SPIRE_Server_API to retrieve the registration entry matching the workload's SPIFFE_ID
2. WHEN the SPIRE_Server_API returns a registration entry, THE Billet_Resolver SHALL extract the selectors from that entry
3. THE Billet_Resolver SHALL include the extracted selectors as a `selectors` field (array of strings) in the local Cedar authorization request context
4. IF the SPIRE_Server_API is unreachable, THEN THE Billet_Resolver SHALL proceed with billet resolution using an empty selectors set and log a warning
5. IF no registration entry exists for the SPIFFE_ID, THEN THE Billet_Resolver SHALL proceed with an empty selectors set and log a warning
6. Cedar policies SHALL be able to reference `context.selectors` to condition billet assignment on workload selectors (e.g., `context.selectors.contains("k8s:ns:finance")`)


### Requirement 27: Platform-Specific Workload Entity Construction

**User Story:** As a platform operator, I want Quartermaster to detect the workload's platform from SPIRE selectors and construct the appropriate typed entity (K8sWorkload, Ec2Workload, or GcpWorkload) with platform-specific attributes, so that Cedar policies can reference platform-specific fields for fine-grained billet assignment.

#### Acceptance Criteria

1. WHEN constructing the ephemeral workload entity for local Cedar evaluation, THE Billet_Resolver SHALL detect the platform from SPIRE selectors using priority order: selectors prefixed with `k8s:` indicate K8sWorkload (highest priority), else selectors prefixed with `aws:` indicate Ec2Workload, else selectors prefixed with `gcp:` indicate GcpWorkload, else base Workload
2. WHEN platform selectors indicate Kubernetes, THE Billet_Resolver SHALL construct a `Quartermaster::K8sWorkload` entity with attributes: namespace, service_account, pod_labels, container_name, node_name (extracted from selectors)
3. WHEN platform selectors indicate AWS EC2, THE Billet_Resolver SHALL construct a `Quartermaster::Ec2Workload` entity with attributes: instance_id, account_id, ami_id, instance_tags, security_groups (extracted from selectors)
4. WHEN platform selectors indicate GCP, THE Billet_Resolver SHALL construct a `Quartermaster::GcpWorkload` entity with attributes: project_id, zone, service_account_email, instance_name (extracted from selectors)
5. IF no platform-specific selectors are present, THE Billet_Resolver SHALL construct a base `Quartermaster::Workload` entity with only the common attributes
6. ALL ephemeral workload entities SHALL include the common attributes: spiffe_id, trust_domain, environment, region, selectors
7. THE ephemeral workload entity SHALL NOT be persisted — it is constructed fresh at authorization-time from SVID claims and SPIRE selectors
8. WHEN multiple platform-specific selector prefixes are present (e.g., both `k8s:` and `aws:` for an EKS pod), THE Billet_Resolver SHALL select the highest-priority platform type and include ALL selectors regardless of platform in the entity's selectors attribute and context
9. WHEN constructing a platform-specific entity (K8sWorkload, Ec2Workload, or GcpWorkload), THE Billet_Resolver SHALL register the entity in the Cedar entities context with the base Workload entity as a parent, so that Cedar policies using `principal is Workload` match all platform subtypes

### Requirement 28: Billet Metadata Endpoint

**User Story:** As a workload developer, I want to query the metadata of billets I hold (including associated cloud roles), so that I can discover which cloud IAM roles or service accounts a billet maps to without consulting external documentation.

#### Acceptance Criteria

1. THE Token_Exchange_Endpoint SHALL serve billet metadata at `GET /billets/{name}`
2. WHEN a request is received at `/billets/{name}`, THE system SHALL require a valid Quartermaster JWT in the `Authorization` header using the `Bearer` scheme
3. WHEN a request is received at `/billets/{name}`, THE system SHALL evaluate a local Cedar `readBillet` authorization request where the caller's billets become `Quartermaster::Billet` principals and the target billet is the resource
4. IF the local evaluation returns "Allow" for at least one of the caller's billets (including a billet reading its own metadata), THEN THE system SHALL return the billet's metadata
5. WHEN the billet exists and authorization succeeds, THE system SHALL return HTTP 200 with the billet's `name`, `description`, `associated_aws_roles`, and `associated_gcp_sas` fields in the response body
6. IF the specified billet name does not exist, THEN THE system SHALL return HTTP 404
7. IF the caller lacks authorization to read the billet, THEN THE system SHALL return HTTP 403
8. A Cedar policy SHALL exist permitting any billet to `readBillet` itself (self-read policy)
