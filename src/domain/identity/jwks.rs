use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::identity::IdentityConfig;
use crate::domain::identity::IdentityError;

use super::oidc::JwksProvider;

/// Google's public JWKS endpoint for verifying GCP identity tokens.
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Manages JWKS for all JWT-based identity sources.
/// Each source has independent refresh cadence and staleness threshold.
pub struct JwksManager {
    sources: HashMap<String, JwksSource>,
    http_client: reqwest::Client,
}

/// State for a single JWKS source (e.g., one OIDC IdP, SPIRE, or Google).
struct JwksSource {
    /// Cached decoding keys from the JWKS endpoint.
    keys: Arc<RwLock<Vec<DecodingKey>>>,
    /// The URL to fetch JWKS from.
    jwks_url: String,
    /// How often to refresh keys.
    refresh_interval: Duration,
    /// Maximum staleness before rejecting tokens.
    max_staleness: Duration,
    /// Last successful refresh time.
    last_refresh: Arc<RwLock<Option<Instant>>>,
}

/// Standard OIDC discovery document (subset).
#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    jwks_uri: String,
}

/// Standard JWKS JSON format.
#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwkKey>,
}

/// A single JWK key entry from a JWKS endpoint.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JwkKey {
    /// Key type (e.g., "RSA", "EC")
    kty: String,
    /// Key ID
    #[serde(default)]
    kid: Option<String>,
    /// Algorithm (e.g., "RS256")
    #[serde(default)]
    alg: Option<String>,
    /// Key use (e.g., "sig")
    #[serde(rename = "use")]
    #[serde(default)]
    key_use: Option<String>,
    // RSA parameters
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC parameters
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

impl JwksManager {
    /// Construct a JwksManager from the application's identity configuration.
    ///
    /// Registers one source per OIDC IdP (keyed by its prefix) and one for GCP
    /// (keyed as "google") if GCP is configured and enabled.
    pub fn from_config(config: &IdentityConfig, http_client: reqwest::Client) -> Self {
        let mut sources = HashMap::new();

        // Register each OIDC IdP source
        for oidc in &config.oidc {
            let jwks_url = format!(
                "{}/.well-known/openid-configuration",
                oidc.issuer.trim_end_matches('/')
            );
            sources.insert(
                oidc.prefix.clone(),
                JwksSource {
                    keys: Arc::new(RwLock::new(Vec::new())),
                    jwks_url,
                    refresh_interval: oidc.jwks_refresh_interval,
                    max_staleness: oidc.max_staleness,
                    last_refresh: Arc::new(RwLock::new(None)),
                },
            );
        }

        // Register Google JWKS source if GCP is configured
        if let Some(gcp) = &config.gcp {
            if gcp.enabled {
                sources.insert(
                    "google".to_string(),
                    JwksSource {
                        keys: Arc::new(RwLock::new(Vec::new())),
                        jwks_url: GOOGLE_JWKS_URL.to_string(),
                        refresh_interval: gcp.jwks_refresh_interval,
                        max_staleness: gcp.max_staleness,
                        last_refresh: Arc::new(RwLock::new(None)),
                    },
                );
            }
        }

        Self {
            sources,
            http_client,
        }
    }

    /// Start background refresh tasks for all registered sources.
    ///
    /// Each source gets its own tokio task that periodically fetches fresh JWKS.
    /// On success, cached keys and last_refresh are updated.
    /// On failure, a warning is logged and old keys remain cached.
    pub fn start_refresh_tasks(&self) {
        for (source_id, source) in &self.sources {
            let source_id = source_id.clone();
            let jwks_url = source.jwks_url.clone();
            let refresh_interval = source.refresh_interval;
            let keys = Arc::clone(&source.keys);
            let last_refresh = Arc::clone(&source.last_refresh);
            let client = self.http_client.clone();

            tokio::spawn(async move {
                // Perform initial fetch immediately
                Self::refresh_source(&source_id, &jwks_url, &client, &keys, &last_refresh).await;

                // Then loop on the configured interval
                let mut interval = tokio::time::interval(refresh_interval);
                // Skip the first tick since we just refreshed
                interval.tick().await;

                loop {
                    interval.tick().await;
                    Self::refresh_source(
                        &source_id,
                        &jwks_url,
                        &client,
                        &keys,
                        &last_refresh,
                    )
                    .await;
                }
            });
        }
    }

    /// Perform a single refresh for one source.
    async fn refresh_source(
        source_id: &str,
        jwks_url: &str,
        client: &reqwest::Client,
        keys: &Arc<RwLock<Vec<DecodingKey>>>,
        last_refresh: &Arc<RwLock<Option<Instant>>>,
    ) {
        match Self::fetch_keys(source_id, jwks_url, client).await {
            Ok(new_keys) => {
                let key_count = new_keys.len();
                let mut keys_guard = keys.write().await;
                *keys_guard = new_keys;
                drop(keys_guard);

                let mut lr_guard = last_refresh.write().await;
                *lr_guard = Some(Instant::now());
                drop(lr_guard);

                info!(
                    source_id = source_id,
                    key_count = key_count,
                    "JWKS refresh successful"
                );
            }
            Err(e) => {
                warn!(
                    source_id = source_id,
                    error = %e,
                    "JWKS refresh failed, continuing with cached keys"
                );
            }
        }
    }

    /// Fetch and parse JWKS keys from the given URL.
    ///
    /// For OIDC discovery URLs (ending in `/.well-known/openid-configuration`),
    /// first fetches the discovery document to get the `jwks_uri`, then fetches
    /// the actual JWKS from that URI.
    ///
    /// For direct JWKS URLs (like Google's), fetches keys directly.
    async fn fetch_keys(
        source_id: &str,
        jwks_url: &str,
        client: &reqwest::Client,
    ) -> Result<Vec<DecodingKey>, String> {
        let actual_jwks_url = if jwks_url.contains("/.well-known/openid-configuration") {
            // This is an OIDC discovery URL — fetch the discovery document first
            let discovery_response = client
                .get(jwks_url)
                .send()
                .await
                .map_err(|e| format!("failed to fetch OIDC discovery for {}: {}", source_id, e))?;

            if !discovery_response.status().is_success() {
                return Err(format!(
                    "OIDC discovery returned {} for {}",
                    discovery_response.status(),
                    source_id
                ));
            }

            let discovery: OidcDiscoveryDocument = discovery_response
                .json()
                .await
                .map_err(|e| format!("failed to parse OIDC discovery for {}: {}", source_id, e))?;

            discovery.jwks_uri
        } else {
            // Direct JWKS URL (e.g., Google's)
            jwks_url.to_string()
        };

        // Fetch the JWKS document
        let jwks_response = client
            .get(&actual_jwks_url)
            .send()
            .await
            .map_err(|e| format!("failed to fetch JWKS for {}: {}", source_id, e))?;

        if !jwks_response.status().is_success() {
            return Err(format!(
                "JWKS endpoint returned {} for {}",
                jwks_response.status(),
                source_id
            ));
        }

        let jwks: JwksDocument = jwks_response
            .json()
            .await
            .map_err(|e| format!("failed to parse JWKS for {}: {}", source_id, e))?;

        // Convert JWK entries to DecodingKeys
        let mut decoding_keys = Vec::new();
        for jwk in &jwks.keys {
            // Skip keys that are not for signing
            if let Some(ref key_use) = jwk.key_use {
                if key_use != "sig" {
                    continue;
                }
            }

            match jwk.kty.as_str() {
                "RSA" => {
                    if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
                        match DecodingKey::from_rsa_components(n, e) {
                            Ok(key) => decoding_keys.push(key),
                            Err(e) => {
                                warn!(
                                    source_id = source_id,
                                    kid = ?jwk.kid,
                                    error = %e,
                                    "failed to parse RSA JWK, skipping"
                                );
                            }
                        }
                    }
                }
                "EC" => {
                    if let (Some(x), Some(y), Some(crv)) = (&jwk.x, &jwk.y, &jwk.crv) {
                        match DecodingKey::from_ec_components(x, y) {
                            Ok(key) => decoding_keys.push(key),
                            Err(e) => {
                                warn!(
                                    source_id = source_id,
                                    kid = ?jwk.kid,
                                    crv = crv,
                                    error = %e,
                                    "failed to parse EC JWK, skipping"
                                );
                            }
                        }
                    }
                }
                other => {
                    warn!(
                        source_id = source_id,
                        kty = other,
                        kid = ?jwk.kid,
                        "unsupported key type, skipping"
                    );
                }
            }
        }

        Ok(decoding_keys)
    }

    /// Check whether a source's keys are stale (beyond max_staleness).
    /// Useful for health checks and monitoring.
    pub async fn is_stale(&self, source_id: &str) -> bool {
        if let Some(source) = self.sources.get(source_id) {
            let lr_guard = source.last_refresh.read().await;
            match *lr_guard {
                Some(last) => last.elapsed() > source.max_staleness,
                // Never refreshed — considered stale
                None => true,
            }
        } else {
            true
        }
    }
}

#[async_trait]
impl JwksProvider for JwksManager {
    /// Get the decoding keys for a given source.
    ///
    /// Returns cached keys if they exist and are not beyond max_staleness.
    /// Returns `IdentityError::KeysStale` if keys have never been fetched or
    /// have exceeded the staleness threshold.
    async fn get_keys(&self, source_id: &str) -> Result<Vec<DecodingKey>, IdentityError> {
        let source = self
            .sources
            .get(source_id)
            .ok_or_else(|| IdentityError::KeysStale(format!("unknown source: {}", source_id)))?;

        // Check staleness
        let lr_guard = source.last_refresh.read().await;
        match *lr_guard {
            Some(last) => {
                if last.elapsed() > source.max_staleness {
                    return Err(IdentityError::KeysStale(source_id.to_string()));
                }
            }
            None => {
                // Keys have never been successfully fetched
                return Err(IdentityError::KeysStale(source_id.to_string()));
            }
        }
        drop(lr_guard);

        // Return cached keys
        let keys_guard = source.keys.read().await;
        Ok(keys_guard.clone())
    }
}

#[async_trait]
impl JwksProvider for Arc<JwksManager> {
    async fn get_keys(&self, source_id: &str) -> Result<Vec<DecodingKey>, IdentityError> {
        self.as_ref().get_keys(source_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::config::identity::{GcpSourceConfig, IdentityConfig, OidcSourceConfig};

    fn make_test_config() -> IdentityConfig {
        IdentityConfig {
            spire: None,
            oidc: vec![OidcSourceConfig {
                prefix: "okta".to_string(),
                issuer: "https://okta.example.com".to_string(),
                client_ids: vec!["client-1".to_string()],
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
                implicit_claims: vec![],
            }],
            aws_sts: None,
            gcp: Some(GcpSourceConfig {
                enabled: true,
                audience: "quartermaster.example.com".to_string(),
                allowed_projects: None,
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
            }),
        }
    }

    #[test]
    fn test_from_config_registers_oidc_sources() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        assert!(manager.sources.contains_key("okta"));
        assert_eq!(
            manager.sources["okta"].jwks_url,
            "https://okta.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            manager.sources["okta"].refresh_interval,
            Duration::from_secs(3600)
        );
        assert_eq!(
            manager.sources["okta"].max_staleness,
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn test_from_config_registers_google_source() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        assert!(manager.sources.contains_key("google"));
        assert_eq!(manager.sources["google"].jwks_url, GOOGLE_JWKS_URL);
    }

    #[test]
    fn test_from_config_skips_disabled_gcp() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![],
            aws_sts: None,
            gcp: Some(GcpSourceConfig {
                enabled: false,
                audience: "qm.example.com".to_string(),
                allowed_projects: None,
                jwks_refresh_interval: Duration::from_secs(3600),
                max_staleness: Duration::from_secs(86400),
            }),
        };
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        assert!(!manager.sources.contains_key("google"));
    }

    #[test]
    fn test_from_config_trailing_slash_issuer() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![OidcSourceConfig {
                prefix: "azure".to_string(),
                issuer: "https://login.microsoft.com/tenant/v2.0/".to_string(),
                client_ids: vec!["client-1".to_string()],
                jwks_refresh_interval: Duration::from_secs(1800),
                max_staleness: Duration::from_secs(43200),
                implicit_claims: vec![],
            }],
            aws_sts: None,
            gcp: None,
        };
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        // Should not produce double slashes
        assert_eq!(
            manager.sources["azure"].jwks_url,
            "https://login.microsoft.com/tenant/v2.0/.well-known/openid-configuration"
        );
    }

    #[tokio::test]
    async fn test_get_keys_unknown_source_returns_stale_error() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        let result = manager.get_keys("nonexistent").await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_get_keys_never_refreshed_returns_stale_error() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        // Keys have never been fetched (last_refresh is None)
        let result = manager.get_keys("okta").await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_get_keys_returns_cached_keys_when_fresh() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        // Manually inject keys and set last_refresh to simulate a successful refresh
        let source = manager.sources.get("okta").unwrap();

        // Create a test RSA key
        let key = DecodingKey::from_rsa_components(
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "AQAB",
        ).unwrap();

        {
            let mut keys_guard = source.keys.write().await;
            *keys_guard = vec![key];
        }
        {
            let mut lr_guard = source.last_refresh.write().await;
            *lr_guard = Some(Instant::now());
        }

        let result = manager.get_keys("okta").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_get_keys_stale_beyond_max_staleness() {
        let config = IdentityConfig {
            spire: None,
            oidc: vec![OidcSourceConfig {
                prefix: "okta".to_string(),
                issuer: "https://okta.example.com".to_string(),
                client_ids: vec!["client-1".to_string()],
                jwks_refresh_interval: Duration::from_secs(60),
                max_staleness: Duration::from_secs(1), // 1 second staleness for testing
                implicit_claims: vec![],
            }],
            aws_sts: None,
            gcp: None,
        };
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        // Set last_refresh to a time in the past beyond max_staleness
        let source = manager.sources.get("okta").unwrap();
        {
            let mut lr_guard = source.last_refresh.write().await;
            *lr_guard = Some(Instant::now() - Duration::from_secs(5));
        }

        let result = manager.get_keys("okta").await;
        assert!(matches!(result, Err(IdentityError::KeysStale(_))));
    }

    #[tokio::test]
    async fn test_is_stale_unknown_source() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        assert!(manager.is_stale("unknown").await);
    }

    #[tokio::test]
    async fn test_is_stale_never_refreshed() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        assert!(manager.is_stale("okta").await);
    }

    #[tokio::test]
    async fn test_is_stale_fresh() {
        let config = make_test_config();
        let client = reqwest::Client::new();
        let manager = JwksManager::from_config(&config, client);

        let source = manager.sources.get("okta").unwrap();
        {
            let mut lr_guard = source.last_refresh.write().await;
            *lr_guard = Some(Instant::now());
        }

        assert!(!manager.is_stale("okta").await);
    }
}
