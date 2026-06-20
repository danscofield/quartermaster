//! Factory function for constructing a `KeyManager` from configuration.

use std::sync::Arc;

use crate::config::backends::{SigningBackend, SigningBackendConfig};
use crate::datastore::DataStore;

use super::kms_client::{AwsKmsClient, GcpKmsClient};
use super::kms_delegated::KmsDelegatedKeyManager;
use super::memory::MemoryKeyManager;
use super::KeyManager;

/// Builds a `KeyManager` implementation based on the provided signing backend configuration.
///
/// # Backend Selection
///
/// - `Memory`: Loads a static PEM key from the path in `config.memory`. Suitable for
///   development and testing.
/// - `KmsDelegated`: Uses a cloud KMS to attest ephemeral EC P-256 keys that rotate
///   on a configurable interval. Requires either `config.kms_delegated.aws_kms` or
///   `config.kms_delegated.gcp_kms` to be present.
///
/// # Parameters
///
/// - `config`: The signing backend configuration section.
/// - `data_store`: A shared DataStore instance (used by `KmsDelegatedKeyManager` to
///   persist and load ephemeral keys).
/// - `purpose`: Identifies the key purpose (e.g., "signing" or "ca"), passed to
///   `KmsDelegatedKeyManager` for namespacing keys in the DataStore.
///
/// # Errors
///
/// Returns an error string if required configuration sections are missing or if
/// backend initialization fails.
pub async fn build_key_manager(
    config: &SigningBackendConfig,
    data_store: Arc<dyn DataStore>,
    purpose: &str,
) -> Result<Arc<dyn KeyManager>, String> {
    match config.backend {
        SigningBackend::Memory => {
            let memory_config = config.memory.as_ref().ok_or_else(|| {
                "signing backend is 'memory' but [signing.memory] section is missing".to_string()
            })?;

            let manager = MemoryKeyManager::new(memory_config)
                .map_err(|e| format!("failed to initialize memory key manager: {}", e))?;

            Ok(Arc::new(manager))
        }
        SigningBackend::KmsDelegated => {
            let kms_config = config.kms_delegated.as_ref().ok_or_else(|| {
                "signing backend is 'kms_delegated' but [signing.kms_delegated] section is missing"
                    .to_string()
            })?;

            // Build the appropriate KMS client based on sub-configuration
            let kms_client: Arc<dyn super::kms_client::KmsClient> =
                if let Some(aws_kms) = &kms_config.aws_kms {
                    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(aws_config::Region::new(aws_kms.region.clone()))
                        .load()
                        .await;

                    Arc::new(AwsKmsClient::new(&sdk_config, aws_kms.key_arn.clone()))
                } else if let Some(gcp_kms) = &kms_config.gcp_kms {
                    Arc::new(GcpKmsClient::new(gcp_kms.key_name.clone()))
                } else {
                    return Err(
                        "signing backend is 'kms_delegated' but neither \
                         [signing.kms_delegated.aws_kms] nor [signing.kms_delegated.gcp_kms] \
                         is configured"
                            .to_string(),
                    );
                };

            let manager = KmsDelegatedKeyManager::new(
                kms_config.clone(),
                kms_client,
                data_store,
                purpose.to_string(),
            )
            .await
            .map_err(|e| format!("failed to initialize KMS-delegated key manager: {}", e))?;

            Ok(Arc::new(manager))
        }
    }
}
