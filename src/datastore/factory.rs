use std::sync::Arc;

use crate::config::backends::{DataStoreBackend, DataStoreConfig};

use super::dynamodb::DynamoDataStore;
use super::local::LocalDataStore;
use super::DataStore;

/// Builds a `DataStore` implementation based on the provided configuration.
///
/// # Backend Selection
///
/// - `Local`: Uses the path from `config.local` or the default `/var/lib/quartermaster/data`.
/// - `Dynamodb`: Requires `config.dynamodb` to be present; builds the AWS SDK config from the
///   configured region.
/// - `Firestore` (requires `gcp` feature): Requires `config.firestore` to be present.
///
/// # Errors
///
/// Returns an error string if required configuration sections are missing or if backend
/// initialization fails.
pub async fn build_datastore(config: &DataStoreConfig) -> Result<Arc<dyn DataStore>, String> {
    match config.backend {
        DataStoreBackend::Local => {
            let path = config
                .local
                .as_ref()
                .map(|l| l.path.clone())
                .unwrap_or_else(|| "/var/lib/quartermaster/data".to_string());

            let store = LocalDataStore::new(path.into())
                .await
                .map_err(|e| format!("failed to initialize local datastore: {}", e))?;

            Ok(Arc::new(store))
        }
        DataStoreBackend::Dynamodb => {
            let dynamo_config = config
                .dynamodb
                .as_ref()
                .ok_or_else(|| {
                    "datastore backend is 'dynamodb' but [datastore.dynamodb] section is missing"
                        .to_string()
                })?;

            let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(dynamo_config.region.clone()))
                .load()
                .await;

            let store = DynamoDataStore::new(dynamo_config, &sdk_config);
            Ok(Arc::new(store))
        }
        DataStoreBackend::Firestore => {
            build_firestore_datastore(config).await
        }
    }
}

#[cfg(feature = "gcp")]
async fn build_firestore_datastore(config: &DataStoreConfig) -> Result<Arc<dyn DataStore>, String> {
    let firestore_config = config
        .firestore
        .as_ref()
        .ok_or_else(|| {
            "datastore backend is 'firestore' but [datastore.firestore] section is missing"
                .to_string()
        })?;

    let store = super::firestore_store::FirestoreDataStore::new(firestore_config)
        .await
        .map_err(|e| format!("failed to initialize Firestore datastore: {}", e))?;

    Ok(Arc::new(store))
}

#[cfg(not(feature = "gcp"))]
async fn build_firestore_datastore(_config: &DataStoreConfig) -> Result<Arc<dyn DataStore>, String> {
    Err(
        "datastore backend is 'firestore' but the 'gcp' feature is not enabled. \
         Recompile with --features gcp to use Firestore."
            .to_string(),
    )
}
