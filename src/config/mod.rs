use serde::Deserialize;
use std::path::PathBuf;

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The Quartermaster issuer URL (e.g., "https://qm.example.com")
    pub issuer: String,

    /// Token TTL in seconds (default 300)
    #[serde(default = "default_ttl_secs")]
    pub token_ttl_secs: u64,

    /// SPIRE trust domain configuration
    pub spire: SpireConfig,

    /// DynamoDB configuration
    pub dynamo: DynamoConfig,

    /// JWT signing configuration
    pub signing: SigningConfig,

    /// Certificate authority configuration
    pub ca: CaConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Optional Redis configuration (required when cache backend is redis)
    pub redis: Option<RedisConfig>,

    /// Rate limiting configuration
    pub rate: RateConfig,

    /// HTTP server configuration
    pub server: ServerConfig,
}

/// SPIRE trust domain configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SpireConfig {
    /// The SPIFFE trust domain (e.g., "example.com")
    pub trust_domain: String,

    /// Path to the SPIRE trust bundle (JWKS file)
    pub trust_bundle_path: PathBuf,
}

/// DynamoDB configuration for policy and billet storage.
#[derive(Debug, Clone, Deserialize)]
pub struct DynamoConfig {
    /// AWS region for DynamoDB
    pub region: String,

    /// Table name for Cedar policies
    #[serde(default = "default_policies_table")]
    pub policies_table: String,

    /// Table name for billet metadata
    #[serde(default = "default_billets_table")]
    pub billets_table: String,

    /// How often to sync policies from DynamoDB (seconds)
    #[serde(default = "default_policy_sync_interval_secs")]
    pub policy_sync_interval_secs: u64,
}

/// JWT signing configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningConfig {
    /// Signing algorithm (e.g., "ES256")
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    /// Path to the PEM-encoded signing key
    pub key_path: PathBuf,
}

/// Certificate authority configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CaConfig {
    /// Path to the CA private key (PEM)
    pub key_path: PathBuf,

    /// Path to the CA certificate (PEM)
    pub cert_path: PathBuf,

    /// Certificate TTL in seconds
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

/// Cache configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Cache backend type
    #[serde(default)]
    pub backend: CacheBackend,

    /// Cache entry TTL in seconds
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

/// Cache backend type.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    Memory,
    Redis,
}

impl Default for CacheBackend {
    fn default() -> Self {
        Self::Memory
    }
}

/// Redis configuration (used when cache backend is redis).
#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct RateConfig {
    /// Maximum requests per SPIFFE ID per minute
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
}

/// HTTP server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Bind host
    #[serde(default = "default_host")]
    pub host: String,

    /// Bind port
    #[serde(default = "default_port")]
    pub port: u16,
}

// --- Default value functions ---

fn default_policies_table() -> String {
    "quartermaster-policies".to_string()
}

fn default_billets_table() -> String {
    "quartermaster-billets".to_string()
}

fn default_policy_sync_interval_secs() -> u64 {
    30
}

fn default_algorithm() -> String {
    "ES256".to_string()
}

fn default_ttl_secs() -> u64 {
    300
}

fn default_requests_per_minute() -> u32 {
    10
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

// --- Validation ---

/// Configuration validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.message)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Validate the configuration for correctness.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(ConfigError {
                message: "issuer must not be empty".to_string(),
            });
        }

        if self.spire.trust_domain.trim().is_empty() {
            return Err(ConfigError {
                message: "spire.trust_domain must not be empty".to_string(),
            });
        }

        let valid_algorithms = ["ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
        if !valid_algorithms.contains(&self.signing.algorithm.as_str()) {
            return Err(ConfigError {
                message: format!(
                    "signing.algorithm '{}' is not valid; must be one of: {}",
                    self.signing.algorithm,
                    valid_algorithms.join(", ")
                ),
            });
        }

        if self.ca.ttl_secs == 0 {
            return Err(ConfigError {
                message: "ca.ttl_secs must be greater than 0".to_string(),
            });
        }

        if self.token_ttl_secs == 0 {
            return Err(ConfigError {
                message: "token_ttl_secs must be greater than 0".to_string(),
            });
        }

        if self.cache.ttl_secs == 0 {
            return Err(ConfigError {
                message: "cache.ttl_secs must be greater than 0".to_string(),
            });
        }

        if self.dynamo.policy_sync_interval_secs == 0 {
            return Err(ConfigError {
                message: "dynamo.policy_sync_interval_secs must be greater than 0".to_string(),
            });
        }

        if self.dynamo.region.trim().is_empty() {
            return Err(ConfigError {
                message: "dynamo.region must not be empty".to_string(),
            });
        }

        if self.rate.requests_per_minute == 0 {
            return Err(ConfigError {
                message: "rate.requests_per_minute must be greater than 0".to_string(),
            });
        }

        if self.cache.backend == CacheBackend::Redis && self.redis.is_none() {
            return Err(ConfigError {
                message: "redis configuration is required when cache.backend is 'redis'".to_string(),
            });
        }

        Ok(())
    }

    /// Load configuration from a TOML file at the path specified by the
    /// `QM_CONFIG_PATH` environment variable, or fall back to environment
    /// variables prefixed with `QM_`.
    pub fn load() -> Result<Self, ConfigError> {
        if let Ok(path) = std::env::var("QM_CONFIG_PATH") {
            Self::from_toml_file(&path)
        } else {
            Self::from_env()
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError {
            message: format!("failed to read config file '{}': {}", path, e),
        })?;
        let config: Config = toml::from_str(&content).map_err(|e| ConfigError {
            message: format!("failed to parse config file '{}': {}", path, e),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables prefixed with `QM_`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = env_required("QM_ISSUER")?;

        let spire = SpireConfig {
            trust_domain: env_required("QM_SPIRE_TRUST_DOMAIN")?,
            trust_bundle_path: PathBuf::from(env_required("QM_SPIRE_TRUST_BUNDLE_PATH")?),
        };

        let dynamo = DynamoConfig {
            region: env_required("QM_DYNAMO_REGION")?,
            policies_table: env_or_default("QM_DYNAMO_POLICIES_TABLE", default_policies_table()),
            billets_table: env_or_default("QM_DYNAMO_BILLETS_TABLE", default_billets_table()),
            policy_sync_interval_secs: env_parse_or_default(
                "QM_DYNAMO_POLICY_SYNC_INTERVAL_SECS",
                default_policy_sync_interval_secs(),
            )?,
        };

        let signing = SigningConfig {
            algorithm: env_or_default("QM_SIGNING_ALGORITHM", default_algorithm()),
            key_path: PathBuf::from(env_required("QM_SIGNING_KEY_PATH")?),
        };

        let ca = CaConfig {
            key_path: PathBuf::from(env_required("QM_CA_KEY_PATH")?),
            cert_path: PathBuf::from(env_required("QM_CA_CERT_PATH")?),
            ttl_secs: env_parse_or_default("QM_CA_TTL_SECS", default_ttl_secs())?,
        };

        let cache = CacheConfig {
            backend: match env_or_default("QM_CACHE_BACKEND", "memory".to_string()).as_str() {
                "redis" => CacheBackend::Redis,
                _ => CacheBackend::Memory,
            },
            ttl_secs: env_parse_or_default("QM_CACHE_TTL_SECS", default_ttl_secs())?,
        };

        let redis = std::env::var("QM_REDIS_URL").ok().map(|url| RedisConfig { url });

        let rate = RateConfig {
            requests_per_minute: env_parse_or_default(
                "QM_RATE_REQUESTS_PER_MINUTE",
                default_requests_per_minute(),
            )?,
        };

        let server = ServerConfig {
            host: env_or_default("QM_SERVER_HOST", default_host()),
            port: env_parse_or_default("QM_SERVER_PORT", default_port())?,
        };

        let config = Config {
            issuer,
            token_ttl_secs: env_parse_or_default("QM_TOKEN_TTL_SECS", default_ttl_secs())?,
            spire,
            dynamo,
            signing,
            ca,
            cache,
            redis,
            rate,
            server,
        };

        config.validate()?;
        Ok(config)
    }
}

/// Read a required environment variable.
fn env_required(key: &str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError {
        message: format!("required environment variable '{}' is not set", key),
    })
}

/// Read an environment variable with a default fallback.
fn env_or_default(key: &str, default: String) -> String {
    std::env::var(key).unwrap_or(default)
}

/// Parse an environment variable as a given type, or use a default.
fn env_parse_or_default<T: std::str::FromStr>(key: &str, default: T) -> Result<T, ConfigError> {
    match std::env::var(key) {
        Ok(val) => val.parse::<T>().map_err(|_| ConfigError {
            message: format!("environment variable '{}' has invalid value '{}'", key, val),
        }),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            issuer: "https://qm.example.com".to_string(),
            token_ttl_secs: 300,
            spire: SpireConfig {
                trust_domain: "example.com".to_string(),
                trust_bundle_path: PathBuf::from("/etc/spire/bundle.json"),
            },
            dynamo: DynamoConfig {
                region: "us-east-1".to_string(),
                policies_table: "quartermaster-policies".to_string(),
                billets_table: "quartermaster-billets".to_string(),
                policy_sync_interval_secs: 30,
            },
            signing: SigningConfig {
                algorithm: "ES256".to_string(),
                key_path: PathBuf::from("/etc/qm/signing.pem"),
            },
            ca: CaConfig {
                key_path: PathBuf::from("/etc/qm/ca.key"),
                cert_path: PathBuf::from("/etc/qm/ca.crt"),
                ttl_secs: 300,
            },
            cache: CacheConfig {
                backend: CacheBackend::Memory,
                ttl_secs: 300,
            },
            redis: None,
            rate: RateConfig {
                requests_per_minute: 10,
            },
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
        }
    }

    #[test]
    fn test_valid_config_passes_validation() {
        let config = valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_empty_issuer_fails_validation() {
        let mut config = valid_config();
        config.issuer = "".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("issuer must not be empty"));
    }

    #[test]
    fn test_whitespace_issuer_fails_validation() {
        let mut config = valid_config();
        config.issuer = "   ".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("issuer must not be empty"));
    }

    #[test]
    fn test_invalid_algorithm_fails_validation() {
        let mut config = valid_config();
        config.signing.algorithm = "INVALID".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("signing.algorithm"));
    }

    #[test]
    fn test_zero_ca_ttl_fails_validation() {
        let mut config = valid_config();
        config.ca.ttl_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("ca.ttl_secs must be greater than 0"));
    }

    #[test]
    fn test_zero_cache_ttl_fails_validation() {
        let mut config = valid_config();
        config.cache.ttl_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("cache.ttl_secs must be greater than 0"));
    }

    #[test]
    fn test_zero_policy_sync_interval_fails_validation() {
        let mut config = valid_config();
        config.dynamo.policy_sync_interval_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("policy_sync_interval_secs must be greater than 0"));
    }

    #[test]
    fn test_empty_region_fails_validation() {
        let mut config = valid_config();
        config.dynamo.region = "".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("dynamo.region must not be empty"));
    }

    #[test]
    fn test_zero_rate_limit_fails_validation() {
        let mut config = valid_config();
        config.rate.requests_per_minute = 0;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("rate.requests_per_minute must be greater than 0"));
    }

    #[test]
    fn test_redis_backend_without_redis_config_fails() {
        let mut config = valid_config();
        config.cache.backend = CacheBackend::Redis;
        config.redis = None;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("redis configuration is required"));
    }

    #[test]
    fn test_redis_backend_with_redis_config_passes() {
        let mut config = valid_config();
        config.cache.backend = CacheBackend::Redis;
        config.redis = Some(RedisConfig {
            url: "redis://localhost:6379".to_string(),
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization() {
        let toml_content = r#"
issuer = "https://qm.example.com"

[spire]
trust_domain = "example.com"
trust_bundle_path = "/etc/spire/bundle.json"

[dynamo]
region = "us-east-1"

[signing]
key_path = "/etc/qm/signing.pem"

[ca]
key_path = "/etc/qm/ca.key"
cert_path = "/etc/qm/ca.crt"

[cache]

[rate]

[server]
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.issuer, "https://qm.example.com");
        assert_eq!(config.spire.trust_domain, "example.com");
        assert_eq!(config.dynamo.region, "us-east-1");
        assert_eq!(config.dynamo.policies_table, "quartermaster-policies");
        assert_eq!(config.dynamo.billets_table, "quartermaster-billets");
        assert_eq!(config.dynamo.policy_sync_interval_secs, 30);
        assert_eq!(config.signing.algorithm, "ES256");
        assert_eq!(config.ca.ttl_secs, 300);
        assert_eq!(config.cache.backend, CacheBackend::Memory);
        assert_eq!(config.cache.ttl_secs, 300);
        assert!(config.redis.is_none());
        assert_eq!(config.rate.requests_per_minute, 10);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_with_all_fields() {
        let toml_content = r#"
issuer = "https://qm.prod.example.com"

[spire]
trust_domain = "prod.example.com"
trust_bundle_path = "/opt/spire/bundle.json"

[dynamo]
region = "eu-west-1"
policies_table = "custom-policies"
billets_table = "custom-billets"
policy_sync_interval_secs = 60

[signing]
algorithm = "ES384"
key_path = "/opt/keys/signing.pem"

[ca]
key_path = "/opt/ca/key.pem"
cert_path = "/opt/ca/cert.pem"
ttl_secs = 600

[cache]
backend = "redis"
ttl_secs = 120

[redis]
url = "redis://redis.internal:6379"

[rate]
requests_per_minute = 50

[server]
host = "127.0.0.1"
port = 9090
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.issuer, "https://qm.prod.example.com");
        assert_eq!(config.spire.trust_domain, "prod.example.com");
        assert_eq!(config.dynamo.region, "eu-west-1");
        assert_eq!(config.dynamo.policies_table, "custom-policies");
        assert_eq!(config.dynamo.billets_table, "custom-billets");
        assert_eq!(config.dynamo.policy_sync_interval_secs, 60);
        assert_eq!(config.signing.algorithm, "ES384");
        assert_eq!(config.ca.ttl_secs, 600);
        assert_eq!(config.cache.backend, CacheBackend::Redis);
        assert_eq!(config.cache.ttl_secs, 120);
        assert_eq!(config.redis.as_ref().unwrap().url, "redis://redis.internal:6379");
        assert_eq!(config.rate.requests_per_minute, 50);
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_empty_trust_domain_fails_validation() {
        let mut config = valid_config();
        config.spire.trust_domain = "".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("trust_domain must not be empty"));
    }

    #[test]
    fn test_supported_algorithms() {
        let algos = ["ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
        for alg in algos {
            let mut config = valid_config();
            config.signing.algorithm = alg.to_string();
            assert!(config.validate().is_ok(), "algorithm {} should be valid", alg);
        }
    }
}
