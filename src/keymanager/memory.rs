//! In-memory KeyManager implementation wrapping the existing StaticKeyManager.
//!
//! Loads a static EC P-256 private key from a PEM file and provides signing
//! operations with no rotation (suitable for dev/test environments).

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use std::path::Path;

use crate::config::backends::MemorySigningConfig;
use crate::signing::static_key::StaticKeyManager;

use super::{KeyError, KeyHealth, KeyManager};

/// A KeyManager backed by a static in-memory signing key loaded from a PEM file.
///
/// This wraps the existing `StaticKeyManager` to provide the full `KeyManager`
/// trait interface with no-op rotation and always-healthy status.
pub struct MemoryKeyManager {
    inner: StaticKeyManager,
}

impl MemoryKeyManager {
    /// Creates a new `MemoryKeyManager` by loading the PEM key from the path
    /// specified in the configuration.
    pub fn new(config: &MemorySigningConfig) -> Result<Self, KeyError> {
        let path = Path::new(&config.key_path);
        let inner = StaticKeyManager::from_pem_file(path).map_err(|e| {
            KeyError::KeyUnavailable(format!("failed to load signing key from {}: {}", config.key_path, e))
        })?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl KeyManager for MemoryKeyManager {
    fn encoding_key(&self) -> &EncodingKey {
        use crate::signing::SigningManager;
        self.inner.encoding_key()
    }

    fn header(&self) -> &Header {
        use crate::signing::SigningManager;
        self.inner.header()
    }

    fn jwks(&self) -> &Value {
        use crate::signing::SigningManager;
        self.inner.jwks()
    }

    fn key_id(&self) -> &str {
        use crate::signing::SigningManager;
        self.inner.key_id()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }

    async fn health(&self) -> KeyHealth {
        KeyHealth::Healthy
    }

    async fn maybe_rotate(&self) -> Result<(), KeyError> {
        // No-op: static keys never rotate.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Generate a test EC P-256 key pair and return the PEM bytes.
    fn generate_test_ec_key_pem() -> Vec<u8> {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("failed to generate test key");

        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_doc.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem.into_bytes()
    }

    fn create_temp_key_file() -> NamedTempFile {
        let pem = generate_test_ec_key_pem();
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(&pem).expect("failed to write key");
        file.flush().expect("failed to flush");
        file
    }

    #[test]
    fn test_memory_key_manager_new_success() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        assert!(!manager.key_id().is_empty());
    }

    #[test]
    fn test_memory_key_manager_new_invalid_path() {
        let config = MemorySigningConfig {
            key_path: "/nonexistent/path/to/key.pem".to_string(),
        };

        let result = MemoryKeyManager::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_key_manager_algorithm() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        assert_eq!(manager.algorithm(), Algorithm::ES256);
    }

    #[tokio::test]
    async fn test_memory_key_manager_health() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        assert_eq!(manager.health().await, KeyHealth::Healthy);
    }

    #[tokio::test]
    async fn test_memory_key_manager_maybe_rotate_is_noop() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        let result = manager.maybe_rotate().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_key_manager_delegates_header() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        let header = manager.header();
        assert_eq!(header.alg, Algorithm::ES256);
        assert!(header.kid.is_some());
        assert_eq!(header.kid.as_deref(), Some(manager.key_id()));
    }

    #[test]
    fn test_memory_key_manager_delegates_jwks() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        let jwks = manager.jwks();
        let keys = jwks["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], manager.key_id());
        assert_eq!(keys[0]["alg"], "ES256");
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["crv"], "P-256");
    }

    #[test]
    fn test_memory_key_manager_encoding_key_usable() {
        let key_file = create_temp_key_file();
        let config = MemorySigningConfig {
            key_path: key_file.path().to_str().unwrap().to_string(),
        };

        let manager = MemoryKeyManager::new(&config).expect("should create manager");
        // Verify we can get the encoding key without panicking
        let _ = manager.encoding_key();
    }
}
