pub mod backends;
pub mod identity;

use serde::Deserialize;
use std::path::PathBuf;

use crate::domain::audit::config::AuditConfig;

pub use backends::{
    AwsKmsConfig, DataStoreBackend, DataStoreConfig, DynamoDbConfig, FirestoreConfig,
    GcpKmsConfig, KmsDelegatedConfig, LocalStoreConfig, MemorySigningConfig, SigningBackend,
    SigningBackendConfig,
};
pub use identity::{
    AwsStsSourceConfig, GcpSourceConfig, IdentityConfig, IdentityConfigError,
    ImplicitClaimConfig, OidcSourceConfig, PathPatternConfig, SpireSourceConfig,
};

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The Quartermaster issuer URL (e.g., "https://qm.example.com")
    pub issuer: String,

    /// Token TTL in seconds (default 300)
    #[serde(default = "default_ttl_secs")]
    pub token_ttl_secs: u64,

    /// SPIRE trust domain configuration (optional; not needed if using other identity sources)
    pub spire: Option<SpireConfig>,

    /// DynamoDB configuration (legacy; optional when [datastore] is configured)
    pub dynamo: Option<DynamoConfig>,

    /// JWT signing configuration (legacy; kept for backward compatibility during migration)
    pub signing: SigningConfig,

    /// Certificate authority configuration (legacy; kept for backward compatibility during migration)
    pub ca: CaConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Optional Redis configuration (required when cache backend is redis)
    pub redis: Option<RedisConfig>,

    /// Rate limiting configuration
    pub rate: RateConfig,

    /// HTTP server configuration
    pub server: ServerConfig,

    /// Audit logging configuration (optional; defaults to stdout sink)
    pub audit: Option<AuditConfig>,

    /// New pluggable DataStore backend configuration (optional; uses legacy `dynamo` if absent)
    pub datastore: Option<DataStoreConfig>,

    /// New pluggable signing backend configuration (optional; uses legacy `signing` if absent)
    pub signing_backend: Option<SigningBackendConfig>,

    /// New pluggable CA backend configuration (optional; uses legacy `ca` if absent)
    pub ca_backend: Option<SigningBackendConfig>,

    /// Identity source configuration (optional; defines how workloads authenticate).
    pub identity: Option<IdentityConfig>,

    /// System billets exempt from resource scope validation.
    /// Defaults to ["quartermaster-admin", "quartermaster-guardrails"] if omitted.
    #[serde(default = "default_system_billets")]
    pub system_billets: Vec<String>,
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
#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    #[default]
    Memory,
    Redis,
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

/// TLS configuration for the server listener.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded server certificate.
    pub cert_path: String,
    /// Path to the PEM-encoded server private key.
    pub key_path: String,
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

    /// Optional separate bind address for admin routes (e.g., "127.0.0.1:9090").
    /// When set, admin endpoints are served on this address instead of the main server.
    pub admin_addr: Option<String>,

    /// Optional TLS configuration. If absent, the server listens on plain HTTP.
    pub tls: Option<TlsConfig>,
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

fn default_system_billets() -> Vec<String> {
    vec![
        "quartermaster-admin".to_string(),
        "quartermaster-guardrails".to_string(),
    ]
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

        if let Some(ref spire) = self.spire {
            if spire.trust_domain.trim().is_empty() {
                return Err(ConfigError {
                    message: "spire.trust_domain must not be empty".to_string(),
                });
            }
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

        if let Some(ref dynamo) = self.dynamo {
            if dynamo.policy_sync_interval_secs == 0 {
                return Err(ConfigError {
                    message: "dynamo.policy_sync_interval_secs must be greater than 0".to_string(),
                });
            }

            if dynamo.region.trim().is_empty() {
                return Err(ConfigError {
                    message: "dynamo.region must not be empty".to_string(),
                });
            }
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

        // Validate new backend config sections when present
        if let Some(ref ds) = self.datastore {
            self.validate_datastore_config(ds)?;
        }

        if let Some(ref sb) = self.signing_backend {
            self.validate_signing_backend_config(sb, "signing_backend")?;
        }

        if let Some(ref cb) = self.ca_backend {
            self.validate_signing_backend_config(cb, "ca_backend")?;
        }

        // Validate identity config when present
        if let Some(ref identity) = self.identity {
            identity.validate().map_err(|err| ConfigError {
                message: format!("identity: {}", err),
            })?;
        }

        Ok(())
    }

    /// Validate a DataStore backend configuration section.
    fn validate_datastore_config(&self, config: &DataStoreConfig) -> Result<(), ConfigError> {
        match config.backend {
            DataStoreBackend::Dynamodb => {
                if config.dynamodb.is_none() {
                    return Err(ConfigError {
                        message: "datastore.dynamodb configuration is required when backend is 'dynamodb'".to_string(),
                    });
                }
                let dynamo = config.dynamodb.as_ref().unwrap();
                if dynamo.region.trim().is_empty() {
                    return Err(ConfigError {
                        message: "datastore.dynamodb.region must not be empty".to_string(),
                    });
                }
            }
            DataStoreBackend::Firestore => {
                if config.firestore.is_none() {
                    return Err(ConfigError {
                        message: "datastore.firestore configuration is required when backend is 'firestore'".to_string(),
                    });
                }
                let fs = config.firestore.as_ref().unwrap();
                if fs.project.trim().is_empty() {
                    return Err(ConfigError {
                        message: "datastore.firestore.project must not be empty".to_string(),
                    });
                }
            }
            DataStoreBackend::Local => {
                // Local backend has sensible defaults; no required sub-config
            }
        }
        Ok(())
    }

    /// Validate a signing backend configuration section.
    fn validate_signing_backend_config(&self, config: &SigningBackendConfig, section: &str) -> Result<(), ConfigError> {
        match config.backend {
            SigningBackend::Memory => {
                if config.memory.is_none() {
                    return Err(ConfigError {
                        message: format!("{}.memory configuration is required when backend is 'memory'", section),
                    });
                }
                let mem = config.memory.as_ref().unwrap();
                if mem.key_path.trim().is_empty() {
                    return Err(ConfigError {
                        message: format!("{}.memory.key_path must not be empty", section),
                    });
                }
            }
            SigningBackend::KmsDelegated => {
                if config.kms_delegated.is_none() {
                    return Err(ConfigError {
                        message: format!("{}.kms_delegated configuration is required when backend is 'kms_delegated'", section),
                    });
                }
                let kms = config.kms_delegated.as_ref().unwrap();
                // Must have at least one KMS provider configured
                if kms.aws_kms.is_none() && kms.gcp_kms.is_none() {
                    return Err(ConfigError {
                        message: format!("{}.kms_delegated must have either aws_kms or gcp_kms configured", section),
                    });
                }
                if let Some(ref aws) = kms.aws_kms {
                    if aws.key_arn.trim().is_empty() {
                        return Err(ConfigError {
                            message: format!("{}.kms_delegated.aws_kms.key_arn must not be empty", section),
                        });
                    }
                    if aws.region.trim().is_empty() {
                        return Err(ConfigError {
                            message: format!("{}.kms_delegated.aws_kms.region must not be empty", section),
                        });
                    }
                }
                if let Some(ref gcp) = kms.gcp_kms {
                    if gcp.key_name.trim().is_empty() {
                        return Err(ConfigError {
                            message: format!("{}.kms_delegated.gcp_kms.key_name must not be empty", section),
                        });
                    }
                }
            }
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
            admin_addr: None,
            tls: None,
        };

        let config = Config {
            issuer,
            token_ttl_secs: env_parse_or_default("QM_TOKEN_TTL_SECS", default_ttl_secs())?,
            spire: Some(spire),
            dynamo: Some(dynamo),
            signing,
            ca,
            cache,
            redis,
            rate,
            server,
            audit: None,
            datastore: None,
            signing_backend: None,
            ca_backend: None,
            identity: None,
            system_billets: default_system_billets(),
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
            spire: Some(SpireConfig {
                trust_domain: "example.com".to_string(),
                trust_bundle_path: PathBuf::from("/etc/spire/bundle.json"),
            }),
            dynamo: Some(DynamoConfig {
                region: "us-east-1".to_string(),
                policies_table: "quartermaster-policies".to_string(),
                billets_table: "quartermaster-billets".to_string(),
                policy_sync_interval_secs: 30,
            }),
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
                admin_addr: None,
                tls: None,
            },
            audit: None,
            datastore: None,
            signing_backend: None,
            ca_backend: None,
            identity: None,
            system_billets: default_system_billets(),
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
        config.dynamo.as_mut().unwrap().policy_sync_interval_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("policy_sync_interval_secs must be greater than 0"));
    }

    #[test]
    fn test_empty_region_fails_validation() {
        let mut config = valid_config();
        config.dynamo.as_mut().unwrap().region = "".to_string();
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
        assert_eq!(config.spire.as_ref().unwrap().trust_domain, "example.com");
        assert_eq!(config.dynamo.as_ref().unwrap().region, "us-east-1");
        assert_eq!(config.dynamo.as_ref().unwrap().policies_table, "quartermaster-policies");
        assert_eq!(config.dynamo.as_ref().unwrap().billets_table, "quartermaster-billets");
        assert_eq!(config.dynamo.as_ref().unwrap().policy_sync_interval_secs, 30);
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
        assert_eq!(config.spire.as_ref().unwrap().trust_domain, "prod.example.com");
        assert_eq!(config.dynamo.as_ref().unwrap().region, "eu-west-1");
        assert_eq!(config.dynamo.as_ref().unwrap().policies_table, "custom-policies");
        assert_eq!(config.dynamo.as_ref().unwrap().billets_table, "custom-billets");
        assert_eq!(config.dynamo.as_ref().unwrap().policy_sync_interval_secs, 60);
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
        config.spire.as_mut().unwrap().trust_domain = "".to_string();
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

    // --- New backend config tests ---

    #[test]
    fn test_toml_deserialization_with_datastore_section() {
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

[datastore]
backend = "dynamodb"

[datastore.dynamodb]
region = "us-west-2"
billets_table = "my-billets"
policies_table = "my-policies"
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let ds = config.datastore.as_ref().unwrap();
        assert_eq!(ds.backend, DataStoreBackend::Dynamodb);
        let dynamo = ds.dynamodb.as_ref().unwrap();
        assert_eq!(dynamo.region, "us-west-2");
        assert_eq!(dynamo.billets_table, "my-billets");
        assert_eq!(dynamo.policies_table, "my-policies");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_with_signing_backend_section() {
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

[signing_backend]
backend = "memory"

[signing_backend.memory]
key_path = "/etc/qm/new-signing.pem"
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let sb = config.signing_backend.as_ref().unwrap();
        assert_eq!(sb.backend, SigningBackend::Memory);
        let mem = sb.memory.as_ref().unwrap();
        assert_eq!(mem.key_path, "/etc/qm/new-signing.pem");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_with_ca_backend_section() {
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

[ca_backend]
backend = "kms_delegated"

[ca_backend.kms_delegated]
rotation_interval = "12h"
key_overlap = "48h"
ephemeral_algorithm = "ES384"

[ca_backend.kms_delegated.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789:key/ca-key"
region = "us-east-1"
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let cb = config.ca_backend.as_ref().unwrap();
        assert_eq!(cb.backend, SigningBackend::KmsDelegated);
        let kms = cb.kms_delegated.as_ref().unwrap();
        assert_eq!(kms.rotation_interval, "12h");
        assert_eq!(kms.key_overlap, "48h");
        assert_eq!(kms.ephemeral_algorithm, "ES384");
        let aws = kms.aws_kms.as_ref().unwrap();
        assert_eq!(aws.key_arn, "arn:aws:kms:us-east-1:123456789:key/ca-key");
        assert_eq!(aws.region, "us-east-1");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_with_all_new_backend_sections() {
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

[datastore]
backend = "firestore"

[datastore.firestore]
project = "my-gcp-project"
collection_prefix = "qm-prod"

[signing_backend]
backend = "kms_delegated"

[signing_backend.kms_delegated]

[signing_backend.kms_delegated.gcp_kms]
key_name = "projects/my-project/locations/global/keyRings/ring/cryptoKeys/signing"

[ca_backend]
backend = "memory"

[ca_backend.memory]
key_path = "/etc/qm/ca-new.pem"
"#;
        let config: Config = toml::from_str(toml_content).unwrap();

        let ds = config.datastore.as_ref().unwrap();
        assert_eq!(ds.backend, DataStoreBackend::Firestore);
        let fs = ds.firestore.as_ref().unwrap();
        assert_eq!(fs.project, "my-gcp-project");
        assert_eq!(fs.collection_prefix, "qm-prod");

        let sb = config.signing_backend.as_ref().unwrap();
        assert_eq!(sb.backend, SigningBackend::KmsDelegated);
        let kms = sb.kms_delegated.as_ref().unwrap();
        assert_eq!(kms.rotation_interval, "6h"); // default
        let gcp = kms.gcp_kms.as_ref().unwrap();
        assert_eq!(gcp.key_name, "projects/my-project/locations/global/keyRings/ring/cryptoKeys/signing");

        let cb = config.ca_backend.as_ref().unwrap();
        assert_eq!(cb.backend, SigningBackend::Memory);
        let mem = cb.memory.as_ref().unwrap();
        assert_eq!(mem.key_path, "/etc/qm/ca-new.pem");

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_without_new_sections_is_backward_compatible() {
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
        assert!(config.datastore.is_none());
        assert!(config.signing_backend.is_none());
        assert!(config.ca_backend.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_datastore_dynamodb_without_config_fails_validation() {
        let mut config = valid_config();
        config.datastore = Some(DataStoreConfig {
            backend: DataStoreBackend::Dynamodb,
            dynamodb: None,
            firestore: None,
            local: None,
            policy_sync_interval_secs: 30,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("datastore.dynamodb configuration is required"));
    }

    #[test]
    fn test_datastore_dynamodb_empty_region_fails_validation() {
        let mut config = valid_config();
        config.datastore = Some(DataStoreConfig {
            backend: DataStoreBackend::Dynamodb,
            dynamodb: Some(DynamoDbConfig {
                region: "".to_string(),
                billets_table: "billets".to_string(),
                policies_table: "policies".to_string(),
            }),
            firestore: None,
            local: None,
            policy_sync_interval_secs: 30,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("datastore.dynamodb.region must not be empty"));
    }

    #[test]
    fn test_datastore_firestore_without_config_fails_validation() {
        let mut config = valid_config();
        config.datastore = Some(DataStoreConfig {
            backend: DataStoreBackend::Firestore,
            dynamodb: None,
            firestore: None,
            local: None,
            policy_sync_interval_secs: 30,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("datastore.firestore configuration is required"));
    }

    #[test]
    fn test_datastore_firestore_empty_project_fails_validation() {
        let mut config = valid_config();
        config.datastore = Some(DataStoreConfig {
            backend: DataStoreBackend::Firestore,
            dynamodb: None,
            firestore: Some(FirestoreConfig {
                project: "  ".to_string(),
                collection_prefix: "qm".to_string(),
            }),
            local: None,
            policy_sync_interval_secs: 30,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("datastore.firestore.project must not be empty"));
    }

    #[test]
    fn test_datastore_local_passes_without_sub_config() {
        let mut config = valid_config();
        config.datastore = Some(DataStoreConfig {
            backend: DataStoreBackend::Local,
            dynamodb: None,
            firestore: None,
            local: None,
            policy_sync_interval_secs: 30,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_signing_backend_memory_without_config_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::Memory,
            memory: None,
            kms_delegated: None,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("signing_backend.memory configuration is required"));
    }

    #[test]
    fn test_signing_backend_memory_empty_key_path_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::Memory,
            memory: Some(MemorySigningConfig {
                key_path: "  ".to_string(),
            }),
            kms_delegated: None,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("signing_backend.memory.key_path must not be empty"));
    }

    #[test]
    fn test_signing_backend_kms_without_config_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::KmsDelegated,
            memory: None,
            kms_delegated: None,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("signing_backend.kms_delegated configuration is required"));
    }

    #[test]
    fn test_signing_backend_kms_without_provider_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::KmsDelegated,
            memory: None,
            kms_delegated: Some(KmsDelegatedConfig {
                rotation_interval: "6h".to_string(),
                key_overlap: "24h".to_string(),
                ephemeral_algorithm: "ES256".to_string(),
                aws_kms: None,
                gcp_kms: None,
            }),
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("must have either aws_kms or gcp_kms configured"));
    }

    #[test]
    fn test_signing_backend_kms_empty_aws_key_arn_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::KmsDelegated,
            memory: None,
            kms_delegated: Some(KmsDelegatedConfig {
                rotation_interval: "6h".to_string(),
                key_overlap: "24h".to_string(),
                ephemeral_algorithm: "ES256".to_string(),
                aws_kms: Some(AwsKmsConfig {
                    key_arn: "".to_string(),
                    region: "us-east-1".to_string(),
                }),
                gcp_kms: None,
            }),
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("aws_kms.key_arn must not be empty"));
    }

    #[test]
    fn test_signing_backend_kms_empty_gcp_key_name_fails_validation() {
        let mut config = valid_config();
        config.signing_backend = Some(SigningBackendConfig {
            backend: SigningBackend::KmsDelegated,
            memory: None,
            kms_delegated: Some(KmsDelegatedConfig {
                rotation_interval: "6h".to_string(),
                key_overlap: "24h".to_string(),
                ephemeral_algorithm: "ES256".to_string(),
                aws_kms: None,
                gcp_kms: Some(GcpKmsConfig {
                    key_name: "  ".to_string(),
                }),
            }),
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("gcp_kms.key_name must not be empty"));
    }

    #[test]
    fn test_ca_backend_memory_without_config_fails_validation() {
        let mut config = valid_config();
        config.ca_backend = Some(SigningBackendConfig {
            backend: SigningBackend::Memory,
            memory: None,
            kms_delegated: None,
        });
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("ca_backend.memory configuration is required"));
    }

    #[test]
    fn test_ca_backend_kms_with_valid_aws_passes() {
        let mut config = valid_config();
        config.ca_backend = Some(SigningBackendConfig {
            backend: SigningBackend::KmsDelegated,
            memory: None,
            kms_delegated: Some(KmsDelegatedConfig {
                rotation_interval: "6h".to_string(),
                key_overlap: "24h".to_string(),
                ephemeral_algorithm: "ES256".to_string(),
                aws_kms: Some(AwsKmsConfig {
                    key_arn: "arn:aws:kms:us-east-1:123456789:key/abc-123".to_string(),
                    region: "us-east-1".to_string(),
                }),
                gcp_kms: None,
            }),
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_deserialization_with_datastore_local_default() {
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

[datastore]
backend = "local"
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        let ds = config.datastore.as_ref().unwrap();
        assert_eq!(ds.backend, DataStoreBackend::Local);
        assert!(ds.local.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_system_billets_defaults_when_omitted_from_toml() {
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
        assert_eq!(
            config.system_billets,
            vec!["quartermaster-admin".to_string(), "quartermaster-guardrails".to_string()]
        );
    }

    #[test]
    fn test_system_billets_custom_list_overrides_defaults() {
        let toml_content = r#"
issuer = "https://qm.example.com"
system_billets = ["my-admin", "my-guardrails", "extra-system"]

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
        assert_eq!(
            config.system_billets,
            vec!["my-admin".to_string(), "my-guardrails".to_string(), "extra-system".to_string()]
        );
    }
}
