//! Key manager trait and error types for cryptographic signing operations.

pub mod factory;
pub mod kms_client;
pub mod kms_delegated;
pub mod memory;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

use crate::signing::SigningManager;

/// Errors from key management operations.
#[derive(Debug, Clone)]
pub enum KeyError {
    /// Key material could not be loaded or generated.
    KeyUnavailable(String),
    /// Signing operation failed.
    SigningFailed(String),
    /// KMS communication failure (degraded state).
    KmsUnavailable(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::KeyUnavailable(msg) => write!(f, "key unavailable: {}", msg),
            KeyError::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            KeyError::KmsUnavailable(msg) => write!(f, "KMS unavailable: {}", msg),
        }
    }
}

impl std::error::Error for KeyError {}

/// Health status for the key manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyHealth {
    /// Key is fresh and within rotation interval.
    Healthy,
    /// Key is functional but older than expected (KMS may be unreachable).
    Degraded { reason: String },
    /// No usable key available.
    Unhealthy { reason: String },
}

/// Trait for managing cryptographic signing keys.
///
/// Implementations provide key material for JWT and certificate signing,
/// publish JWKS for verification, and handle key rotation.
#[async_trait]
pub trait KeyManager: Send + Sync {
    /// Returns the current encoding key for JWT/cert signing.
    fn encoding_key(&self) -> &EncodingKey;

    /// Returns the JWT header (includes kid, alg).
    fn header(&self) -> &Header;

    /// Returns the full JWKS (current + overlapping previous keys).
    fn jwks(&self) -> &Value;

    /// Returns the current active key's ID.
    fn key_id(&self) -> &str;

    /// Returns the signing algorithm.
    fn algorithm(&self) -> Algorithm;

    /// Check health of the key manager (rotation freshness, KMS reachability).
    async fn health(&self) -> KeyHealth;

    /// Trigger a key rotation check. No-op for memory backend.
    /// For kms_delegated: checks if rotation is due and performs it.
    async fn maybe_rotate(&self) -> Result<(), KeyError>;
}

/// Adapter that exposes a `KeyManager` as a `SigningManager` for backward compatibility.
///
/// Code that expects the synchronous `SigningManager` trait (e.g., the token handler)
/// can use this adapter to delegate to any `KeyManager` implementation without changes.
pub struct SigningManagerAdapter {
    key_manager: Arc<dyn KeyManager>,
}

impl SigningManagerAdapter {
    /// Create a new adapter wrapping the given `KeyManager`.
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self { key_manager }
    }
}

impl SigningManager for SigningManagerAdapter {
    fn encoding_key(&self) -> &EncodingKey {
        self.key_manager.encoding_key()
    }

    fn header(&self) -> &Header {
        self.key_manager.header()
    }

    fn jwks(&self) -> &Value {
        self.key_manager.jwks()
    }

    fn key_id(&self) -> &str {
        self.key_manager.key_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A minimal KeyManager implementation for testing the adapter.
    struct FakeKeyManager {
        encoding_key: EncodingKey,
        header: Header,
        jwks: Value,
        key_id: String,
    }

    impl FakeKeyManager {
        fn new() -> Self {
            // Generate a test EC P-256 key for the encoding key
            let rng = ring::rand::SystemRandom::new();
            let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .expect("failed to generate test key");

            // Create PEM from PKCS8
            let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_doc.as_ref());
            let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str("-----END PRIVATE KEY-----\n");

            let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
                .expect("failed to create encoding key");

            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("test-kid-123".to_string());

            let jwks = serde_json::json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "test-kid-123",
                    "alg": "ES256",
                    "use": "sig",
                    "x": "placeholder-x",
                    "y": "placeholder-y",
                }]
            });

            Self {
                encoding_key,
                header,
                jwks,
                key_id: "test-kid-123".to_string(),
            }
        }
    }

    #[async_trait]
    impl KeyManager for FakeKeyManager {
        fn encoding_key(&self) -> &EncodingKey {
            &self.encoding_key
        }

        fn header(&self) -> &Header {
            &self.header
        }

        fn jwks(&self) -> &Value {
            &self.jwks
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn algorithm(&self) -> Algorithm {
            Algorithm::ES256
        }

        async fn health(&self) -> KeyHealth {
            KeyHealth::Healthy
        }

        async fn maybe_rotate(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    #[test]
    fn test_adapter_delegates_encoding_key() {
        let km = Arc::new(FakeKeyManager::new());
        let adapter = SigningManagerAdapter::new(km.clone());

        // We can't compare EncodingKey directly, but we can verify it doesn't panic
        let _ = adapter.encoding_key();
    }

    #[test]
    fn test_adapter_delegates_header() {
        let km = Arc::new(FakeKeyManager::new());
        let adapter = SigningManagerAdapter::new(km.clone());

        let header = adapter.header();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("test-kid-123"));
    }

    #[test]
    fn test_adapter_delegates_jwks() {
        let km = Arc::new(FakeKeyManager::new());
        let adapter = SigningManagerAdapter::new(km.clone());

        let jwks = adapter.jwks();
        let keys = jwks["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "test-kid-123");
    }

    #[test]
    fn test_adapter_delegates_key_id() {
        let km = Arc::new(FakeKeyManager::new());
        let adapter = SigningManagerAdapter::new(km.clone());

        assert_eq!(adapter.key_id(), "test-kid-123");
    }
}
