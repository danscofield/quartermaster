use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

use crate::domain::identity::path_pattern::{PathPatternError, PathPatternMatcher};

/// Top-level identity source configuration.
/// At least one source must be configured.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// SPIRE identity source configuration (optional).
    pub spire: Option<SpireSourceConfig>,

    /// Corporate OIDC IdP sources (zero or more).
    #[serde(default)]
    pub oidc: Vec<OidcSourceConfig>,

    /// AWS presigned STS identity source (optional).
    pub aws_sts: Option<AwsStsSourceConfig>,

    /// GCP identity token source (optional).
    pub gcp: Option<GcpSourceConfig>,
}

/// SPIRE identity source configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SpireSourceConfig {
    /// The SPIFFE trust domain (e.g., "example.com")
    pub trust_domain: String,

    /// Path to the SPIRE trust bundle (JWKS file) or URL
    pub jwks_path: String,

    /// Optional SPIRE server address for selector enrichment
    /// (e.g., "unix:///run/spire/server/api.sock")
    pub server_addr: Option<String>,

    /// Expected audience in SVIDs
    pub audience: String,

    /// Optional path to PEM-encoded CA certificates for X.509-SVID chain validation.
    /// These are the root/intermediate CAs that issued the X.509-SVIDs.
    /// Distinct from `jwks_path`, which provides JWT signing keys for JWT-SVID verification.
    /// When absent, mTLS identity source is disabled.
    pub x509_bundle_path: Option<String>,

    /// Path patterns for extracting attributes from SPIFFE ID paths.
    /// When non-empty, SPIRE Server API calls are skipped entirely.
    #[serde(default)]
    pub path_patterns: Vec<PathPatternConfig>,
}

/// A single SPIFFE ID path pattern with a regex containing named capture groups.
#[derive(Debug, Clone, Deserialize)]
pub struct PathPatternConfig {
    /// Regex pattern with named capture groups (e.g., `(?P<namespace>[^/]+)`).
    /// Applied to the SPIFFE ID path (after stripping `spiffe://<trust_domain>`).
    pub pattern: String,
}

/// Configuration for a single OIDC identity provider source.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcSourceConfig {
    /// Unique prefix for this IdP (alphanumeric + hyphens, lowercase)
    pub prefix: String,

    /// OIDC issuer URL (e.g., "https://mycompany.okta.com/oauth2/default")
    pub issuer: String,

    /// Allowed client IDs (audiences) for token validation
    pub client_ids: Vec<String>,

    /// How often to refresh JWKS from discovery URL (e.g., "1h")
    #[serde(deserialize_with = "deserialize_duration")]
    pub jwks_refresh_interval: Duration,

    /// Maximum time JWKS can be stale before rejecting tokens (e.g., "24h")
    #[serde(deserialize_with = "deserialize_duration")]
    pub max_staleness: Duration,

    /// Implicit claim-to-billet mappings (zero or more)
    #[serde(default)]
    pub implicit_claims: Vec<ImplicitClaimConfig>,
}

/// Configuration for mapping a single token claim to implicit billets.
#[derive(Debug, Clone, Deserialize)]
pub struct ImplicitClaimConfig {
    /// Name of the token claim to map (e.g., "groups", "roles")
    pub claim: String,

    /// Prefix for derived billets (e.g., "okta-group" → billets "okta-group:<value>")
    pub billet_prefix: String,

    /// Whether derived billets appear in issued JWTs/certs.
    /// If false, billets are used for admin Cedar evaluation only.
    #[serde(default = "default_in_tokens")]
    pub in_tokens: bool,
}

/// AWS presigned STS identity source configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsStsSourceConfig {
    /// Whether this source is enabled
    pub enabled: bool,

    /// Optional allowlist of AWS account IDs.
    /// If None, any account is accepted.
    pub allowed_accounts: Option<Vec<String>>,
}

/// GCP identity token source configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GcpSourceConfig {
    /// Whether this source is enabled
    pub enabled: bool,

    /// Expected audience in GCP identity tokens
    pub audience: String,

    /// Optional allowlist of GCP project IDs.
    /// If None, any project is accepted.
    pub allowed_projects: Option<Vec<String>>,

    /// How often to refresh Google's JWKS (e.g., "1h")
    #[serde(deserialize_with = "deserialize_duration")]
    pub jwks_refresh_interval: Duration,

    /// Maximum time JWKS can be stale before rejecting tokens (e.g., "24h")
    #[serde(deserialize_with = "deserialize_duration")]
    pub max_staleness: Duration,
}

fn default_in_tokens() -> bool {
    true
}

/// Errors that can occur during identity configuration validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityConfigError {
    /// No identity sources are configured (all absent or disabled).
    NoSourcesConfigured,
    /// Two or more OIDC sources share the same prefix.
    DuplicateOidcPrefix(String),
    /// Two or more implicit claim mappings share the same billet_prefix.
    DuplicateBilletPrefix(String),
    /// A prefix (IdP or billet) does not match the required pattern.
    InvalidPrefix {
        prefix: String,
        context: String,
    },
    /// An OIDC issuer URL is not a valid URL.
    InvalidIssuerUrl {
        prefix: String,
        issuer: String,
        reason: String,
    },
}

impl std::fmt::Display for IdentityConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSourcesConfigured => {
                write!(f, "at least one identity source must be configured")
            }
            Self::DuplicateOidcPrefix(prefix) => {
                write!(f, "duplicate OIDC IdP prefix: '{}'", prefix)
            }
            Self::DuplicateBilletPrefix(prefix) => {
                write!(f, "duplicate implicit claim billet_prefix: '{}'", prefix)
            }
            Self::InvalidPrefix { prefix, context } => {
                write!(
                    f,
                    "invalid prefix '{}' ({}): must match pattern [a-z0-9][a-z0-9-]*",
                    prefix, context
                )
            }
            Self::InvalidIssuerUrl {
                prefix,
                issuer,
                reason,
            } => {
                write!(
                    f,
                    "invalid OIDC issuer URL for prefix '{}': '{}' ({})",
                    prefix, issuer, reason
                )
            }
        }
    }
}

impl std::error::Error for IdentityConfigError {}

/// Check whether a prefix matches the pattern `[a-z0-9][a-z0-9-]*`.
fn is_valid_prefix(prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let bytes = prefix.as_bytes();
    // First character must be [a-z0-9]
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    // Remaining characters must be [a-z0-9-]
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl IdentityConfig {
    /// Validate the identity configuration at startup.
    ///
    /// Checks:
    /// 1. At least one identity source is configured (SPIRE present, or OIDC non-empty,
    ///    or aws_sts enabled, or gcp enabled).
    /// 2. All OIDC IdP `prefix` values are unique.
    /// 3. All `billet_prefix` values across all implicit claim mappings are globally unique.
    /// 4. All IdP prefixes and billet prefixes match the pattern `[a-z0-9][a-z0-9-]*`.
    /// 5. All OIDC issuer URLs are valid (parseable as URLs).
    pub fn validate(&self) -> Result<(), IdentityConfigError> {
        // 1. At least one source must be configured
        let has_spire = self.spire.is_some();
        let has_oidc = !self.oidc.is_empty();
        let has_aws_sts = self
            .aws_sts
            .as_ref()
            .map(|a| a.enabled)
            .unwrap_or(false);
        let has_gcp = self.gcp.as_ref().map(|g| g.enabled).unwrap_or(false);

        if !has_spire && !has_oidc && !has_aws_sts && !has_gcp {
            return Err(IdentityConfigError::NoSourcesConfigured);
        }

        // 2. Unique OIDC IdP prefixes
        let mut seen_prefixes: HashSet<&str> = HashSet::new();
        for source in &self.oidc {
            if !seen_prefixes.insert(&source.prefix) {
                return Err(IdentityConfigError::DuplicateOidcPrefix(
                    source.prefix.clone(),
                ));
            }
        }

        // 3. Unique billet_prefix values across ALL implicit claim mappings
        let mut seen_billet_prefixes: HashSet<&str> = HashSet::new();
        for source in &self.oidc {
            for mapping in &source.implicit_claims {
                if !seen_billet_prefixes.insert(&mapping.billet_prefix) {
                    return Err(IdentityConfigError::DuplicateBilletPrefix(
                        mapping.billet_prefix.clone(),
                    ));
                }
            }
        }

        // 4. Validate prefix patterns
        for source in &self.oidc {
            if !is_valid_prefix(&source.prefix) {
                return Err(IdentityConfigError::InvalidPrefix {
                    prefix: source.prefix.clone(),
                    context: format!("OIDC IdP prefix for issuer '{}'", source.issuer),
                });
            }
            for mapping in &source.implicit_claims {
                if !is_valid_prefix(&mapping.billet_prefix) {
                    return Err(IdentityConfigError::InvalidPrefix {
                        prefix: mapping.billet_prefix.clone(),
                        context: format!(
                            "billet_prefix for claim '{}' in OIDC IdP '{}'",
                            mapping.claim, source.prefix
                        ),
                    });
                }
            }
        }

        // 5. Validate OIDC issuer URLs
        for source in &self.oidc {
            if let Err(e) = Url::parse(&source.issuer) {
                return Err(IdentityConfigError::InvalidIssuerUrl {
                    prefix: source.prefix.clone(),
                    issuer: source.issuer.clone(),
                    reason: e.to_string(),
                });
            }
        }

        Ok(())
    }
}

impl SpireSourceConfig {
    /// Validates path patterns at startup.
    /// Returns compiled PathPatternMatcher on success, or errors on failure.
    pub fn validate_path_patterns(
        &self,
    ) -> Result<Option<PathPatternMatcher>, Vec<PathPatternError>> {
        if self.path_patterns.is_empty() {
            return Ok(None);
        }
        PathPatternMatcher::compile(&self.trust_domain, &self.path_patterns).map(Some)
    }
}

/// Deserialize a human-readable duration string into `std::time::Duration`.
///
/// Supported formats:
/// - `"30s"` — seconds
/// - `"5m"` — minutes
/// - `"1h"` — hours
/// - `"24h"` — hours
/// - `"7d"` — days
///
/// Bare numbers (without suffix) are treated as seconds.
pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

/// Parse a human-readable duration string into `std::time::Duration`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("duration string must not be empty".to_string());
    }

    // Try to split into numeric part and suffix
    let (num_str, suffix) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, "ms")
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, "h")
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, "d")
    } else {
        // Bare number — treat as seconds
        (s, "s")
    };

    let value: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration value: '{}'", s))?;

    let duration = match suffix {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        "h" => Duration::from_secs(value * 3600),
        "d" => Duration::from_secs(value * 86400),
        _ => return Err(format!("unknown duration suffix in: '{}'", s)),
    };

    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Validation helper functions ─────────────────────────────────────────

    /// Helper to create a minimal valid OIDC source config.
    fn oidc_source(prefix: &str, issuer: &str) -> OidcSourceConfig {
        OidcSourceConfig {
            prefix: prefix.to_string(),
            issuer: issuer.to_string(),
            client_ids: vec!["client-1".to_string()],
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
            implicit_claims: vec![],
        }
    }

    /// Helper to create an implicit claim config.
    fn implicit_claim(claim: &str, billet_prefix: &str) -> ImplicitClaimConfig {
        ImplicitClaimConfig {
            claim: claim.to_string(),
            billet_prefix: billet_prefix.to_string(),
            in_tokens: true,
        }
    }

    // ─── Duration parsing tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn test_parse_duration_bare_number() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  1h  ").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_empty_fails() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    #[test]
    fn test_parse_duration_invalid_fails() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("-1h").is_err());
    }

    // ─── Deserialization tests ───────────────────────────────────────────────

    #[test]
    fn test_identity_config_deserialization_full() {
        let toml_content = r#"
[spire]
trust_domain = "example.com"
jwks_path = "/run/spire/agent/jwks.json"
server_addr = "unix:///run/spire/server/api.sock"
audience = "quartermaster.example.com"

[[oidc]]
prefix = "okta"
issuer = "https://mycompany.okta.com/oauth2/default"
client_ids = ["0oa1abc2def3ghi4j5k6"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

[[oidc.implicit_claims]]
claim = "groups"
billet_prefix = "okta-group"
in_tokens = false

[[oidc.implicit_claims]]
claim = "roles"
billet_prefix = "okta-role"
in_tokens = true

[[oidc]]
prefix = "azuread"
issuer = "https://login.microsoftonline.com/tenant-id/v2.0"
client_ids = ["app-client-id-1", "app-client-id-2"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

[aws_sts]
enabled = true
allowed_accounts = ["123456789012", "987654321098"]

[gcp]
enabled = true
audience = "quartermaster.example.com"
allowed_projects = ["my-project-123"]
jwks_refresh_interval = "1h"
max_staleness = "24h"
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();

        // SPIRE
        let spire = config.spire.unwrap();
        assert_eq!(spire.trust_domain, "example.com");
        assert_eq!(spire.jwks_path, "/run/spire/agent/jwks.json");
        assert_eq!(
            spire.server_addr.as_deref(),
            Some("unix:///run/spire/server/api.sock")
        );
        assert_eq!(spire.audience, "quartermaster.example.com");

        // OIDC sources
        assert_eq!(config.oidc.len(), 2);

        let okta = &config.oidc[0];
        assert_eq!(okta.prefix, "okta");
        assert_eq!(okta.issuer, "https://mycompany.okta.com/oauth2/default");
        assert_eq!(okta.client_ids, vec!["0oa1abc2def3ghi4j5k6"]);
        assert_eq!(okta.jwks_refresh_interval, Duration::from_secs(3600));
        assert_eq!(okta.max_staleness, Duration::from_secs(86400));
        assert_eq!(okta.implicit_claims.len(), 2);
        assert_eq!(okta.implicit_claims[0].claim, "groups");
        assert_eq!(okta.implicit_claims[0].billet_prefix, "okta-group");
        assert!(!okta.implicit_claims[0].in_tokens);
        assert_eq!(okta.implicit_claims[1].claim, "roles");
        assert_eq!(okta.implicit_claims[1].billet_prefix, "okta-role");
        assert!(okta.implicit_claims[1].in_tokens);

        let azure = &config.oidc[1];
        assert_eq!(azure.prefix, "azuread");
        assert_eq!(
            azure.issuer,
            "https://login.microsoftonline.com/tenant-id/v2.0"
        );
        assert_eq!(azure.client_ids, vec!["app-client-id-1", "app-client-id-2"]);
        assert!(azure.implicit_claims.is_empty());

        // AWS STS
        let aws = config.aws_sts.unwrap();
        assert!(aws.enabled);
        assert_eq!(
            aws.allowed_accounts,
            Some(vec![
                "123456789012".to_string(),
                "987654321098".to_string()
            ])
        );

        // GCP
        let gcp = config.gcp.unwrap();
        assert!(gcp.enabled);
        assert_eq!(gcp.audience, "quartermaster.example.com");
        assert_eq!(
            gcp.allowed_projects,
            Some(vec!["my-project-123".to_string()])
        );
        assert_eq!(gcp.jwks_refresh_interval, Duration::from_secs(3600));
        assert_eq!(gcp.max_staleness, Duration::from_secs(86400));
    }

    #[test]
    fn test_identity_config_spire_only() {
        let toml_content = r#"
[spire]
trust_domain = "example.com"
jwks_path = "/run/spire/agent/jwks.json"
audience = "qm.example.com"
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        assert!(config.spire.is_some());
        assert!(config.oidc.is_empty());
        assert!(config.aws_sts.is_none());
        assert!(config.gcp.is_none());

        // server_addr is optional
        assert!(config.spire.unwrap().server_addr.is_none());
    }

    #[test]
    fn test_identity_config_oidc_no_implicit_claims() {
        let toml_content = r#"
[[oidc]]
prefix = "okta"
issuer = "https://okta.example.com"
client_ids = ["client1"]
jwks_refresh_interval = "30m"
max_staleness = "12h"
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        assert!(config.spire.is_none());
        assert_eq!(config.oidc.len(), 1);
        assert!(config.oidc[0].implicit_claims.is_empty());
        assert_eq!(
            config.oidc[0].jwks_refresh_interval,
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            config.oidc[0].max_staleness,
            Duration::from_secs(12 * 3600)
        );
    }

    #[test]
    fn test_identity_config_aws_sts_no_allowlist() {
        let toml_content = r#"
[aws_sts]
enabled = true
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        let aws = config.aws_sts.unwrap();
        assert!(aws.enabled);
        assert!(aws.allowed_accounts.is_none());
    }

    #[test]
    fn test_identity_config_gcp_no_allowlist() {
        let toml_content = r#"
[gcp]
enabled = true
audience = "qm.example.com"
jwks_refresh_interval = "2h"
max_staleness = "48h"
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        let gcp = config.gcp.unwrap();
        assert!(gcp.enabled);
        assert_eq!(gcp.audience, "qm.example.com");
        assert!(gcp.allowed_projects.is_none());
        assert_eq!(gcp.jwks_refresh_interval, Duration::from_secs(7200));
        assert_eq!(gcp.max_staleness, Duration::from_secs(48 * 3600));
    }

    #[test]
    fn test_implicit_claim_in_tokens_defaults_to_true() {
        let toml_content = r#"
[[oidc]]
prefix = "okta"
issuer = "https://okta.example.com"
client_ids = ["client1"]
jwks_refresh_interval = "1h"
max_staleness = "24h"

[[oidc.implicit_claims]]
claim = "groups"
billet_prefix = "okta-group"
"#;
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        // in_tokens should default to true when not specified
        assert!(config.oidc[0].implicit_claims[0].in_tokens);
    }

    #[test]
    fn test_empty_identity_config() {
        let toml_content = "";
        let config: IdentityConfig = toml::from_str(toml_content).unwrap();
        assert!(config.spire.is_none());
        assert!(config.oidc.is_empty());
        assert!(config.aws_sts.is_none());
        assert!(config.gcp.is_none());
    }

    // ─── Validation tests ────────────────────────────────────────────────────

    #[test]
    fn test_validate_no_sources_configured() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: None,
            gcp: None,
        };
        assert_eq!(
            config.validate().unwrap_err(),
            IdentityConfigError::NoSourcesConfigured
        );
    }

    #[test]
    fn test_validate_disabled_aws_sts_and_gcp_no_other_sources() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: Some(AwsStsSourceConfig {
                enabled: false,
                allowed_accounts: None,
            }),
            gcp: Some(GcpSourceConfig {
                enabled: false,
                audience: "qm.example.com".to_string(),
                allowed_projects: None,
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
            }),
        };
        assert_eq!(
            config.validate().unwrap_err(),
            IdentityConfigError::NoSourcesConfigured
        );
    }

    #[test]
    fn test_validate_spire_only_is_valid() {
        let config = IdentityConfig {
            spire: Some(SpireSourceConfig {
                trust_domain: "example.com".to_string(),
                jwks_path: "/run/spire/bundle.json".to_string(),
                server_addr: None,
                audience: "qm.example.com".to_string(),
                x509_bundle_path: None,
                path_patterns: vec![],
            }),
            oidc: vec![],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_oidc_only_is_valid() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("okta", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_aws_sts_enabled_is_valid() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: Some(AwsStsSourceConfig {
                enabled: true,
                allowed_accounts: None,
            }),
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_gcp_enabled_is_valid() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: None,
            gcp: Some(GcpSourceConfig {
                enabled: true,
                audience: "qm.example.com".to_string(),
                allowed_projects: None,
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
            }),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_duplicate_oidc_prefix() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![
                oidc_source("okta", "https://okta1.example.com"),
                oidc_source("okta", "https://okta2.example.com"),
            ],
            aws_sts: None,
            gcp: None,
        };
        assert_eq!(
            config.validate().unwrap_err(),
            IdentityConfigError::DuplicateOidcPrefix("okta".to_string())
        );
    }

    #[test]
    fn test_validate_unique_oidc_prefixes_pass() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![
                oidc_source("okta", "https://okta.example.com"),
                oidc_source("azuread", "https://login.microsoft.com/tenant/v2.0"),
            ],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_duplicate_billet_prefix_same_source() {
        let mut source = oidc_source("okta", "https://okta.example.com");
        source.implicit_claims = vec![
            implicit_claim("groups", "okta-group"),
            implicit_claim("roles", "okta-group"), // duplicate!
        ];
        let config = IdentityConfig {
            spire: None,
            oidc: vec![source],
            aws_sts: None,
            gcp: None,
        };
        assert_eq!(
            config.validate().unwrap_err(),
            IdentityConfigError::DuplicateBilletPrefix("okta-group".to_string())
        );
    }

    #[test]
    fn test_validate_duplicate_billet_prefix_across_sources() {
        let mut source1 = oidc_source("okta", "https://okta.example.com");
        source1.implicit_claims = vec![implicit_claim("groups", "shared-prefix")];

        let mut source2 = oidc_source("azuread", "https://login.microsoft.com/tenant/v2.0");
        source2.implicit_claims = vec![implicit_claim("groups", "shared-prefix")]; // duplicate!

        let config = IdentityConfig {
            spire: None,
            oidc: vec![source1, source2],
            aws_sts: None,
            gcp: None,
        };
        assert_eq!(
            config.validate().unwrap_err(),
            IdentityConfigError::DuplicateBilletPrefix("shared-prefix".to_string())
        );
    }

    #[test]
    fn test_validate_unique_billet_prefixes_pass() {
        let mut source1 = oidc_source("okta", "https://okta.example.com");
        source1.implicit_claims = vec![
            implicit_claim("groups", "okta-group"),
            implicit_claim("roles", "okta-role"),
        ];

        let mut source2 = oidc_source("azuread", "https://login.microsoft.com/tenant/v2.0");
        source2.implicit_claims = vec![implicit_claim("groups", "azure-group")];

        let config = IdentityConfig {
            spire: None,
            oidc: vec![source1, source2],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_oidc_prefix_uppercase() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("Okta", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidPrefix { prefix, .. } => {
                assert_eq!(prefix, "Okta");
            }
            _ => panic!("expected InvalidPrefix, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_invalid_oidc_prefix_leading_hyphen() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("-okta", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidPrefix { prefix, .. } => {
                assert_eq!(prefix, "-okta");
            }
            _ => panic!("expected InvalidPrefix, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_invalid_oidc_prefix_empty() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidPrefix { prefix, .. } => {
                assert_eq!(prefix, "");
            }
            _ => panic!("expected InvalidPrefix, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_invalid_oidc_prefix_special_chars() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("okta_corp", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidPrefix { prefix, .. } => {
                assert_eq!(prefix, "okta_corp");
            }
            _ => panic!("expected InvalidPrefix, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_invalid_billet_prefix() {
        let mut source = oidc_source("okta", "https://okta.example.com");
        source.implicit_claims = vec![implicit_claim("groups", "Okta-Group")];

        let config = IdentityConfig {
            spire: None,
            oidc: vec![source],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidPrefix { prefix, .. } => {
                assert_eq!(prefix, "Okta-Group");
            }
            _ => panic!("expected InvalidPrefix, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_valid_prefixes() {
        // All these should pass the regex: [a-z0-9][a-z0-9-]*
        let valid_prefixes = vec![
            "a", "okta", "azure-ad", "my-idp-3", "0auth", "1-prefix", "a-b-c",
        ];
        for prefix in valid_prefixes {
            assert!(
                is_valid_prefix(prefix),
                "expected '{}' to be valid",
                prefix
            );
        }
    }

    #[test]
    fn test_validate_invalid_prefixes() {
        let invalid_prefixes = vec![
            "",            // empty
            "-start",      // leading hyphen
            "Upper",       // uppercase
            "has space",   // space
            "under_score", // underscore
            "dot.here",    // dot
            "ALLCAPS",     // all uppercase
        ];
        for prefix in invalid_prefixes {
            assert!(
                !is_valid_prefix(prefix),
                "expected '{}' to be invalid",
                prefix
            );
        }
    }

    #[test]
    fn test_validate_invalid_issuer_url() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("okta", "not a url")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidIssuerUrl {
                prefix, issuer, ..
            } => {
                assert_eq!(prefix, "okta");
                assert_eq!(issuer, "not a url");
            }
            _ => panic!("expected InvalidIssuerUrl, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_issuer_url_no_scheme() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("okta", "okta.example.com/oauth2")],
            aws_sts: None,
            gcp: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            IdentityConfigError::InvalidIssuerUrl { .. } => {}
            _ => panic!("expected InvalidIssuerUrl, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_valid_issuer_urls() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![
                oidc_source("okta", "https://mycompany.okta.com/oauth2/default"),
                oidc_source("azuread", "https://login.microsoftonline.com/tenant-id/v2.0"),
            ],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_full_valid_config() {
        let mut source1 = oidc_source("okta", "https://okta.example.com/oauth2/default");
        source1.implicit_claims = vec![
            implicit_claim("groups", "okta-group"),
            implicit_claim("roles", "okta-role"),
        ];

        let mut source2 =
            oidc_source("azuread", "https://login.microsoftonline.com/tenant/v2.0");
        source2.implicit_claims = vec![implicit_claim("groups", "azure-group")];

        let config = IdentityConfig {
            spire: Some(SpireSourceConfig {
                trust_domain: "example.com".to_string(),
                jwks_path: "/run/spire/bundle.json".to_string(),
                server_addr: None,
                audience: "qm.example.com".to_string(),
                x509_bundle_path: None,
                path_patterns: vec![],
            }),
            oidc: vec![source1, source2],
            aws_sts: Some(AwsStsSourceConfig {
                enabled: true,
                allowed_accounts: Some(vec!["123456789012".to_string()]),
            }),
            gcp: Some(GcpSourceConfig {
                enabled: true,
                audience: "qm.example.com".to_string(),
                allowed_projects: None,
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
            }),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_prefix_with_numbers() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("1auth", "https://1auth.example.com")],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_single_char_prefix() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("a", "https://a.example.com")],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_prefix_trailing_hyphen_is_valid() {
        // The regex [a-z0-9][a-z0-9-]* allows trailing hyphens
        let config = IdentityConfig {
            spire: None,
            oidc: vec![oidc_source("okta-", "https://okta.example.com")],
            aws_sts: None,
            gcp: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_error_display_no_sources() {
        let err = IdentityConfigError::NoSourcesConfigured;
        assert_eq!(
            err.to_string(),
            "at least one identity source must be configured"
        );
    }

    #[test]
    fn test_validate_error_display_duplicate_prefix() {
        let err = IdentityConfigError::DuplicateOidcPrefix("okta".to_string());
        assert_eq!(err.to_string(), "duplicate OIDC IdP prefix: 'okta'");
    }

    #[test]
    fn test_validate_error_display_duplicate_billet_prefix() {
        let err = IdentityConfigError::DuplicateBilletPrefix("okta-group".to_string());
        assert_eq!(
            err.to_string(),
            "duplicate implicit claim billet_prefix: 'okta-group'"
        );
    }

    #[test]
    fn test_validate_error_display_invalid_prefix() {
        let err = IdentityConfigError::InvalidPrefix {
            prefix: "BAD".to_string(),
            context: "OIDC IdP prefix for issuer 'https://x.com'".to_string(),
        };
        assert!(err.to_string().contains("BAD"));
        assert!(err.to_string().contains("[a-z0-9][a-z0-9-]*"));
    }

    #[test]
    fn test_validate_error_display_invalid_url() {
        let err = IdentityConfigError::InvalidIssuerUrl {
            prefix: "okta".to_string(),
            issuer: "bad url".to_string(),
            reason: "relative URL without a base".to_string(),
        };
        assert!(err.to_string().contains("okta"));
        assert!(err.to_string().contains("bad url"));
    }
}
