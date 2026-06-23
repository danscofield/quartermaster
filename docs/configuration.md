# Configuration Guide

Quartermaster is configured via a TOML file. Set the path with `QUARTERMASTER_CONFIG` environment variable (default: `./config.toml`).

## Minimal Configuration (Local Development)

```toml
[quartermaster]
issuer = "http://localhost:8443"
token_ttl = "5m"

[server]
addr = "0.0.0.0:8443"
```

This starts Quartermaster with:
- Local file-backed datastore (`./data/`)
- In-memory signing key (auto-generated if no key path specified)
- Stdout audit logging
- No identity sources (you'll need to add at least one)

## Full Configuration Reference

```toml
# ─── Core ─────────────────────────────────────────────────────────────────────

[quartermaster]
# The issuer URL. Must match what relying parties (AWS STS, GCP WIF) are configured to trust.
# This appears as the `iss` claim in all issued JWTs and in the OIDC discovery document.
issuer = "https://quartermaster.example.com"

# Default token TTL. Workloads can request shorter but not longer.
token_ttl = "1h"

# Additional JWT claims to copy the billets array into.
# Useful for AWS OIDC federation (which supports "amr" as a condition key).
# Default: [] (billets only in the "billets" claim)
# Example: ["amr"] → JWT gets "amr": ["billet1", "billet2"] alongside "billets"
billet_claims = ["amr"]

# ─── Server ───────────────────────────────────────────────────────────────────

[server]
# Address for the main listener (token exchange, OIDC discovery, JWKS, CA bundle, billet metadata)
addr = "0.0.0.0:8443"

# Optional separate address for the admin API. If omitted, admin routes are served on the main listener.
# Useful for network segmentation (admin API only reachable from internal network).
admin_addr = "0.0.0.0:8444"

# ─── Data Store ───────────────────────────────────────────────────────────────

[datastore]
# Backend: "local", "dynamodb", or "firestore"
# Default: "local"
backend = "dynamodb"

# Interval between full scans of the data store to refresh the in-memory PolicySet and billet list.
policy_sync_interval = "30s"

# --- Local file-backed store (default) ---
[datastore.local]
# Directory for JSON files. Created on startup if it doesn't exist.
path = "/var/lib/quartermaster/data"

# --- AWS DynamoDB ---
[datastore.dynamodb]
region = "us-east-1"
billets_table = "quartermaster-billets"     # default
policies_table = "quartermaster-policies"   # default
# Authentication uses the standard AWS credential chain (env vars, IRSA, instance profile, etc.)

# --- Google Cloud Firestore ---
[datastore.firestore]
project = "my-gcp-project"
collection_prefix = "quartermaster"   # creates quartermaster-billets, quartermaster-policies collections
# Authentication uses Application Default Credentials (ADC)

# ─── Signing (JWT) ────────────────────────────────────────────────────────────

[signing]
# Backend: "memory" or "kms_delegated"
# Default: "memory"
backend = "kms_delegated"

# --- In-memory static key (dev/test) ---
[signing.memory]
# Path to a PEM-encoded EC P-256 or RSA private key.
key_path = "/etc/quartermaster/keys/signing.pem"

# --- KMS-delegated ephemeral keys (production) ---
[signing.kms_delegated]
# How often to rotate the ephemeral signing key. KMS is called once per rotation.
rotation_interval = "6h"

# How long old keys remain in JWKS after rotation.
# Set to 24h to accommodate AWS STS JWKS caching.
key_overlap = "24h"

# Algorithm for the ephemeral key.
ephemeral_algorithm = "ES256"

# Choose ONE KMS backend:

[signing.kms_delegated.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
region = "us-east-1"

# OR:
# [signing.kms_delegated.gcp_kms]
# key_name = "projects/my-project/locations/global/keyRings/qm/cryptoKeys/signing/cryptoKeyVersions/1"

# ─── Certificate Authority ────────────────────────────────────────────────────

[ca]
# Backend: "memory" or "kms_delegated" (mirrors signing config structure)
# Default: "memory"
backend = "memory"

# The CA certificate (public) is always loaded from disk regardless of backend.
cert_path = "/etc/quartermaster/keys/ca.cert.pem"
issuer_cn = "Quartermaster CA"
cert_ttl = "1h"   # matches token_ttl by default

# Include billets as OU in certificate Subject (format: qm-billets:billet1:billet2:)
# Enables IAM Roles Anywhere to condition on billets via StringLike on x509Subject/OU.
# Default: false
include_billets_ou = true

# --- In-memory CA key (dev/test) ---
[ca.memory]
key_path = "/etc/quartermaster/keys/ca.key.pem"

# --- KMS-delegated CA key (production) ---
# [ca.kms_delegated]
# rotation_interval = "6h"
# key_overlap = "24h"
# ephemeral_algorithm = "ES256"
#
# [ca.kms_delegated.aws_kms]
# key_arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-def456"
# region = "us-east-1"

# ─── Identity Sources ─────────────────────────────────────────────────────────
#
# At least one identity source must be configured. All are optional individually.

# --- SPIRE (workload identity via SPIFFE SVIDs) ---
[identity.spire]
trust_domain = "example.com"

# Path or URL to SPIRE's JWKS for SVID signature verification.
jwks_path = "/run/spire/agent/jwks.json"

# Expected audience in SVIDs presented to Quartermaster.
audience = "quartermaster.example.com"

# --- Corporate OIDC Identity Providers (zero or more) ---
[[identity.oidc]]
# Unique prefix for this IdP. Used in subject formatting and implicit billet prefixes.
prefix = "okta"

# OIDC issuer URL. Quartermaster fetches .well-known/openid-configuration from here.
issuer = "https://mycompany.okta.com/oauth2/default"

# Allowed audience values (client IDs). Token's `aud` must match one of these.
client_ids = ["0oa1abc2def3ghi4j5k6"]

# How often to refresh the IdP's JWKS.
jwks_refresh_interval = "1h"

# If JWKS hasn't refreshed in this long, reject tokens from this IdP.
max_staleness = "24h"

# --- Implicit billet claim mappings (zero or more per IdP) ---
# Each maps a token claim to prefixed billets.

[[identity.oidc.implicit_claims]]
# Token claim name containing an array of strings (groups, roles, etc.)
claim = "groups"

# Prefix for derived billets. Each claim value becomes "{billet_prefix}:{value}".
# Must be globally unique across all implicit_claims in all IdPs.
billet_prefix = "okta-group"

# Whether these implicit billets appear in issued JWTs/certs.
# false = used for admin Cedar authorization only (not propagated to downstream services).
# true = included in issued tokens.
in_tokens = false

[[identity.oidc.implicit_claims]]
claim = "roles"
billet_prefix = "okta-role"
in_tokens = true

# --- Second IdP example (Azure AD, no implicit mapping) ---
# [[identity.oidc]]
# prefix = "azuread"
# issuer = "https://login.microsoftonline.com/tenant-id/v2.0"
# client_ids = ["app-client-id"]
# jwks_refresh_interval = "1h"
# max_staleness = "24h"

# --- AWS Presigned STS (workload identity without SPIRE) ---
[identity.aws_sts]
enabled = true

# Optional: restrict to specific AWS accounts. If omitted, any account is accepted.
# allowed_accounts = ["123456789012", "987654321098"]

# --- GCP Identity Tokens (workload identity without SPIRE) ---
[identity.gcp]
enabled = true

# Expected audience in GCP identity tokens.
audience = "quartermaster.example.com"

# Optional: restrict to specific GCP projects.
# allowed_projects = ["my-project-123"]

jwks_refresh_interval = "1h"
max_staleness = "24h"

# ─── Cache ────────────────────────────────────────────────────────────────────

[cache]
# Backend: "memory" or "redis"
# Default: "memory"
backend = "memory"

# Cache TTL for billet resolution results. Should match token_ttl.
ttl = "1h"

# --- Redis (for multi-instance deployments) ---
# [cache.redis]
# addr = "redis:6379"
# db = 0

# ─── Rate Limiting ────────────────────────────────────────────────────────────

[rate_limit]
# Maximum token exchange requests per identity per minute.
per_identity = 10

# ─── Audit Logging ────────────────────────────────────────────────────────────

[audit]
# Bounded buffer size for the async event channel. If full, newest events are dropped.
buffer_capacity = 10000

# --- Sinks (one or more; defaults to stdout if omitted) ---

[[audit.sinks]]
type = "stdout"

# [[audit.sinks]]
# type = "file"
# path = "/var/log/quartermaster/audit.jsonl"
# max_size_mb = 100
# max_files = 10

# [[audit.sinks]]
# type = "kinesis_firehose"
# stream_name = "quartermaster-audit"
# region = "us-east-1"

# [[audit.sinks]]
# type = "gcp_pubsub"
# project = "my-project"
# topic = "quartermaster-audit"
```

## Environment Variable Overrides

Any config value can be overridden via environment variables using the pattern `QUARTERMASTER_<SECTION>_<KEY>`:

```bash
QUARTERMASTER_ISSUER=https://qm.prod.example.com
QUARTERMASTER_SERVER_ADDR=0.0.0.0:443
QUARTERMASTER_DATASTORE_BACKEND=dynamodb
QUARTERMASTER_DATASTORE_DYNAMODB_REGION=us-west-2
QUARTERMASTER_SIGNING_BACKEND=kms_delegated
```

## Cloud Credentials

Quartermaster does **not** manage cloud credentials in its config file. It relies on the standard credential chains provided by the AWS and GCP SDKs.

### AWS

The AWS SDK resolves credentials in this order:

1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. EKS Pod Identity / IRSA (recommended for Kubernetes)
3. ECS task role
4. EC2 instance metadata (instance profile)
5. `~/.aws/credentials` file (local development)

**Production (EKS):** Annotate the Quartermaster ServiceAccount with an IAM role:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: quartermaster
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/quartermaster
```

The role needs permissions for: `dynamodb:Scan`, `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem`, `dynamodb:Query`, `dynamodb:BatchWriteItem` on the billets/policies tables, and `kms:Sign`, `kms:GetPublicKey` on the signing/CA keys.

### GCP

The GCP SDK resolves credentials via Application Default Credentials (ADC):

1. `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a service account key JSON
2. GKE Workload Identity (recommended for Kubernetes)
3. Compute Engine metadata service (for VMs)
4. `gcloud auth application-default login` (local development)

**Production (GKE):** Bind the Kubernetes ServiceAccount to a GCP ServiceAccount:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  quartermaster@my-project.iam.gserviceaccount.com \
  --member="serviceAccount:my-project.svc.id.goog[quartermaster-ns/quartermaster]" \
  --role="roles/iam.workloadIdentityUser"
```

The GCP service account needs: `roles/datastore.user` (Firestore), `roles/cloudkms.signerVerifier` (Cloud KMS), and `roles/pubsub.publisher` (if using Pub/Sub audit sink).

### Local Development

No cloud credentials needed if using the default local backends:

```toml
[datastore]
backend = "local"       # file-backed, no cloud

[signing]
backend = "memory"      # static key from PEM file, no KMS

[[audit.sinks]]
type = "stdout"         # no Firehose/PubSub
```

## Deployment Profiles

### Local Development

```toml
[quartermaster]
issuer = "http://localhost:8443"
token_ttl = "5m"

[server]
addr = "0.0.0.0:8443"

[signing.memory]
key_path = "./dev-keys/signing.pem"

[ca.memory]
key_path = "./dev-keys/ca.key.pem"
cert_path = "./dev-keys/ca.cert.pem"

[identity.spire]
trust_domain = "dev.local"
jwks_path = "./dev-keys/spire-jwks.json"
audience = "http://localhost:8443"
```

### Production (AWS)

```toml
[quartermaster]
issuer = "https://quartermaster.example.com"
token_ttl = "1h"

[server]
addr = "0.0.0.0:8443"
admin_addr = "0.0.0.0:8444"

[datastore]
backend = "dynamodb"
policy_sync_interval = "30s"

[datastore.dynamodb]
region = "us-east-1"

[signing]
backend = "kms_delegated"

[signing.kms_delegated]
rotation_interval = "6h"
key_overlap = "24h"
ephemeral_algorithm = "ES256"

[signing.kms_delegated.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
region = "us-east-1"

[ca]
backend = "kms_delegated"
cert_path = "/etc/quartermaster/keys/ca.cert.pem"

[ca.kms_delegated]
rotation_interval = "6h"
key_overlap = "24h"
ephemeral_algorithm = "ES256"

[ca.kms_delegated.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-def456"
region = "us-east-1"

[identity.spire]
trust_domain = "example.com"
jwks_path = "/run/spire/agent/jwks.json"
audience = "quartermaster.example.com"

[[identity.oidc]]
prefix = "okta"
issuer = "https://mycompany.okta.com/oauth2/default"
client_ids = ["0oa1abc2def3ghi4j5k6"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

[[identity.oidc.implicit_claims]]
claim = "groups"
billet_prefix = "okta-group"
in_tokens = false

[cache]
backend = "redis"
ttl = "1h"

[cache.redis]
addr = "redis.internal:6379"
db = 0

[rate_limit]
per_identity = 20

[[audit.sinks]]
type = "stdout"

[[audit.sinks]]
type = "kinesis_firehose"
stream_name = "quartermaster-audit"
region = "us-east-1"
```

### Production (GCP)

```toml
[quartermaster]
issuer = "https://quartermaster.example.com"
token_ttl = "1h"

[server]
addr = "0.0.0.0:8443"
admin_addr = "0.0.0.0:8444"

[datastore]
backend = "firestore"
policy_sync_interval = "30s"

[datastore.firestore]
project = "my-prod-project"
collection_prefix = "quartermaster"

[signing]
backend = "kms_delegated"

[signing.kms_delegated]
rotation_interval = "6h"
key_overlap = "24h"
ephemeral_algorithm = "ES256"

[signing.kms_delegated.gcp_kms]
key_name = "projects/my-prod-project/locations/global/keyRings/quartermaster/cryptoKeys/signing/cryptoKeyVersions/1"

[ca]
backend = "kms_delegated"
cert_path = "/etc/quartermaster/keys/ca.cert.pem"

[ca.kms_delegated]
rotation_interval = "6h"
key_overlap = "24h"
ephemeral_algorithm = "ES256"

[ca.kms_delegated.gcp_kms]
key_name = "projects/my-prod-project/locations/global/keyRings/quartermaster/cryptoKeys/ca/cryptoKeyVersions/1"

[identity.spire]
trust_domain = "example.com"
jwks_path = "/run/spire/agent/jwks.json"
audience = "quartermaster.example.com"

[[identity.oidc]]
prefix = "google"
issuer = "https://accounts.google.com"
client_ids = ["123456789.apps.googleusercontent.com"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

[[identity.oidc.implicit_claims]]
claim = "groups"
billet_prefix = "google-group"
in_tokens = false

[identity.gcp]
enabled = true
audience = "quartermaster.example.com"

[cache]
backend = "memory"
ttl = "1h"

[rate_limit]
per_identity = 20

[[audit.sinks]]
type = "stdout"

[[audit.sinks]]
type = "gcp_pubsub"
project = "my-prod-project"
topic = "quartermaster-audit"
```
