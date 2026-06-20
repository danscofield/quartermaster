use serde::Deserialize;

// ── DataStore Configuration ──

/// Configuration for the DataStore backend selection and settings.
#[derive(Debug, Clone, Deserialize)]
pub struct DataStoreConfig {
    /// Which backend to use for persistent storage.
    #[serde(default = "default_datastore_backend")]
    pub backend: DataStoreBackend,

    /// DynamoDB-specific configuration (required when backend is "dynamodb").
    pub dynamodb: Option<DynamoDbConfig>,

    /// Firestore-specific configuration (required when backend is "firestore").
    pub firestore: Option<FirestoreConfig>,

    /// Local file-backed configuration (optional; uses defaults if absent).
    pub local: Option<LocalStoreConfig>,
}

/// Available DataStore backend types.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DataStoreBackend {
    Dynamodb,
    Firestore,
    Local,
}

fn default_datastore_backend() -> DataStoreBackend {
    DataStoreBackend::Local
}

/// DynamoDB backend configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DynamoDbConfig {
    /// AWS region for DynamoDB.
    pub region: String,

    /// Table name for billet metadata.
    #[serde(default = "default_billets_table")]
    pub billets_table: String,

    /// Table name for Cedar policies.
    #[serde(default = "default_policies_table")]
    pub policies_table: String,
}

/// Firestore backend configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct FirestoreConfig {
    /// GCP project ID.
    pub project: String,

    /// Prefix for Firestore collections.
    #[serde(default = "default_collection_prefix")]
    pub collection_prefix: String,
}

/// Local file-backed DataStore configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LocalStoreConfig {
    /// Directory path for local storage.
    #[serde(default = "default_local_path")]
    pub path: String,
}

// ── Signing Backend Configuration ──

/// Configuration for the signing backend selection and settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningBackendConfig {
    /// Which signing backend to use.
    #[serde(default = "default_signing_backend")]
    pub backend: SigningBackend,

    /// Memory (static PEM key) signing configuration.
    pub memory: Option<MemorySigningConfig>,

    /// KMS-delegated ephemeral key signing configuration.
    pub kms_delegated: Option<KmsDelegatedConfig>,
}

/// Available signing backend types.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SigningBackend {
    Memory,
    #[serde(rename = "kms_delegated")]
    KmsDelegated,
}

fn default_signing_backend() -> SigningBackend {
    SigningBackend::Memory
}

/// Configuration for in-memory static key signing.
#[derive(Debug, Clone, Deserialize)]
pub struct MemorySigningConfig {
    /// Path to the PEM-encoded signing key.
    pub key_path: String,
}

/// Configuration for KMS-delegated ephemeral key signing.
#[derive(Debug, Clone, Deserialize)]
pub struct KmsDelegatedConfig {
    /// How often to rotate the ephemeral signing key (e.g., "6h").
    #[serde(default = "default_rotation_interval")]
    pub rotation_interval: String,

    /// How long the previous key remains in JWKS after rotation (e.g., "24h").
    #[serde(default = "default_key_overlap")]
    pub key_overlap: String,

    /// Algorithm for the ephemeral key (e.g., "ES256").
    #[serde(default = "default_ephemeral_algorithm")]
    pub ephemeral_algorithm: String,

    /// AWS KMS configuration (required when using AWS KMS).
    pub aws_kms: Option<AwsKmsConfig>,

    /// GCP Cloud KMS configuration (required when using GCP KMS).
    pub gcp_kms: Option<GcpKmsConfig>,
}

/// AWS KMS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsKmsConfig {
    /// ARN of the KMS key to use for attestation.
    pub key_arn: String,

    /// AWS region for the KMS key.
    pub region: String,
}

/// GCP Cloud KMS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GcpKmsConfig {
    /// Full resource name of the GCP KMS key.
    pub key_name: String,
}

// ── Default Value Functions ──

fn default_billets_table() -> String {
    "quartermaster-billets".to_string()
}

fn default_policies_table() -> String {
    "quartermaster-policies".to_string()
}

fn default_collection_prefix() -> String {
    "quartermaster".to_string()
}

fn default_local_path() -> String {
    "/var/lib/quartermaster/data".to_string()
}

fn default_rotation_interval() -> String {
    "6h".to_string()
}

fn default_key_overlap() -> String {
    "24h".to_string()
}

fn default_ephemeral_algorithm() -> String {
    "ES256".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datastore_config_defaults() {
        let toml_str = "";
        let config: DataStoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, DataStoreBackend::Local);
        assert!(config.dynamodb.is_none());
        assert!(config.firestore.is_none());
        assert!(config.local.is_none());
    }

    #[test]
    fn test_datastore_config_dynamodb() {
        let toml_str = r#"
backend = "dynamodb"

[dynamodb]
region = "us-east-1"
"#;
        let config: DataStoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, DataStoreBackend::Dynamodb);
        let dynamo = config.dynamodb.unwrap();
        assert_eq!(dynamo.region, "us-east-1");
        assert_eq!(dynamo.billets_table, "quartermaster-billets");
        assert_eq!(dynamo.policies_table, "quartermaster-policies");
    }

    #[test]
    fn test_datastore_config_firestore() {
        let toml_str = r#"
backend = "firestore"

[firestore]
project = "my-gcp-project"
"#;
        let config: DataStoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, DataStoreBackend::Firestore);
        let fs = config.firestore.unwrap();
        assert_eq!(fs.project, "my-gcp-project");
        assert_eq!(fs.collection_prefix, "quartermaster");
    }

    #[test]
    fn test_datastore_config_local_with_custom_path() {
        let toml_str = r#"
backend = "local"

[local]
path = "/tmp/qm-data"
"#;
        let config: DataStoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, DataStoreBackend::Local);
        let local = config.local.unwrap();
        assert_eq!(local.path, "/tmp/qm-data");
    }

    #[test]
    fn test_local_store_config_default_path() {
        let toml_str = "";
        let config: LocalStoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.path, "/var/lib/quartermaster/data");
    }

    #[test]
    fn test_signing_backend_config_defaults() {
        let toml_str = "";
        let config: SigningBackendConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, SigningBackend::Memory);
        assert!(config.memory.is_none());
        assert!(config.kms_delegated.is_none());
    }

    #[test]
    fn test_signing_backend_config_memory() {
        let toml_str = r#"
backend = "memory"

[memory]
key_path = "/etc/qm/signing.pem"
"#;
        let config: SigningBackendConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, SigningBackend::Memory);
        let mem = config.memory.unwrap();
        assert_eq!(mem.key_path, "/etc/qm/signing.pem");
    }

    #[test]
    fn test_signing_backend_config_kms_delegated_defaults() {
        let toml_str = r#"
backend = "kms_delegated"

[kms_delegated]
"#;
        let config: SigningBackendConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, SigningBackend::KmsDelegated);
        let kms = config.kms_delegated.unwrap();
        assert_eq!(kms.rotation_interval, "6h");
        assert_eq!(kms.key_overlap, "24h");
        assert_eq!(kms.ephemeral_algorithm, "ES256");
        assert!(kms.aws_kms.is_none());
        assert!(kms.gcp_kms.is_none());
    }

    #[test]
    fn test_signing_backend_config_kms_with_aws() {
        let toml_str = r#"
backend = "kms_delegated"

[kms_delegated]
rotation_interval = "12h"
key_overlap = "48h"
ephemeral_algorithm = "ES384"

[kms_delegated.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789:key/abc-123"
region = "us-east-1"
"#;
        let config: SigningBackendConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.backend, SigningBackend::KmsDelegated);
        let kms = config.kms_delegated.unwrap();
        assert_eq!(kms.rotation_interval, "12h");
        assert_eq!(kms.key_overlap, "48h");
        assert_eq!(kms.ephemeral_algorithm, "ES384");
        let aws = kms.aws_kms.unwrap();
        assert_eq!(aws.key_arn, "arn:aws:kms:us-east-1:123456789:key/abc-123");
        assert_eq!(aws.region, "us-east-1");
    }

    #[test]
    fn test_signing_backend_config_kms_with_gcp() {
        let toml_str = r#"
backend = "kms_delegated"

[kms_delegated]

[kms_delegated.gcp_kms]
key_name = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
"#;
        let config: SigningBackendConfig = toml::from_str(toml_str).unwrap();
        let kms = config.kms_delegated.unwrap();
        let gcp = kms.gcp_kms.unwrap();
        assert_eq!(
            gcp.key_name,
            "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
        );
    }

    #[test]
    fn test_dynamodb_config_custom_tables() {
        let toml_str = r#"
region = "eu-west-1"
billets_table = "custom-billets"
policies_table = "custom-policies"
"#;
        let config: DynamoDbConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.billets_table, "custom-billets");
        assert_eq!(config.policies_table, "custom-policies");
    }

    #[test]
    fn test_firestore_config_custom_prefix() {
        let toml_str = r#"
project = "prod-project"
collection_prefix = "qm-prod"
"#;
        let config: FirestoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.project, "prod-project");
        assert_eq!(config.collection_prefix, "qm-prod");
    }
}
