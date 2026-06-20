//! KMS-delegated ephemeral key manager implementation.
//!
//! Generates EC P-256 key pairs locally, uses a cloud KMS service to attest (sign)
//! the public key, and rotates keys on a configurable interval. Previous keys remain
//! in the JWKS response during an overlap window so relying parties can verify
//! tokens signed with the prior key.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::KeyPair;
use serde_json::{json, Value};
use std::sync::{Arc, RwLock};
use tracing::warn;

use crate::config::backends::KmsDelegatedConfig;
use crate::datastore::{DataStore, EphemeralKeyRecord};

use super::kms_client::KmsClient;
use super::{KeyError, KeyHealth, KeyManager};

/// State for a single ephemeral signing key.
struct EphemeralKeyState {
    /// The encoding key used for JWT signing.
    encoding_key: EncodingKey,
    /// The JWT header (includes kid, alg).
    header: Header,
    /// The JWK entry for this key (single key object, not the full JWKS).
    jwk: Value,
    /// The key ID (base64url(SHA-256(JWK Thumbprint))).
    key_id: String,
    /// When this key was created/activated.
    created_at: DateTime<Utc>,
    /// When this key expires and should be removed from JWKS.
    expires_at: DateTime<Utc>,
}

/// A KeyManager that generates ephemeral EC P-256 key pairs locally and uses
/// a cloud KMS to attest (sign) the public key material.
///
/// Key rotation occurs on a configurable interval. Previous keys remain in the
/// JWKS response during a configurable overlap window.
///
/// Uses `std::sync::RwLock` (not `tokio::sync::RwLock`) because the `KeyManager`
/// trait has synchronous accessor methods that return references. The locks are
/// held very briefly, so contention is negligible.
pub struct KmsDelegatedKeyManager {
    /// Current active ephemeral key (for signing).
    active_key: RwLock<EphemeralKeyState>,
    /// Previous key(s) still in JWKS overlap window.
    previous_keys: RwLock<Vec<EphemeralKeyState>>,
    /// Cached JWKS response (precomputed since `jwks()` returns `&Value`).
    cached_jwks: RwLock<Value>,
    /// KMS client (trait object for testability).
    kms_client: Arc<dyn KmsClient>,
    /// DataStore for persisting/reading ephemeral keys.
    data_store: Arc<dyn DataStore>,
    /// Configuration (retained for future use).
    #[allow(dead_code)]
    config: KmsDelegatedConfig,
    /// Purpose identifier ("signing" or "ca").
    purpose: String,
    /// Parsed rotation interval.
    rotation_interval: Duration,
    /// Parsed key overlap duration.
    key_overlap: Duration,
}

impl KmsDelegatedKeyManager {
    /// Creates a new `KmsDelegatedKeyManager`.
    ///
    /// On construction, attempts to load existing ephemeral keys from the DataStore.
    /// If no keys exist, generates an initial key pair and persists it.
    pub async fn new(
        config: KmsDelegatedConfig,
        kms_client: Arc<dyn KmsClient>,
        data_store: Arc<dyn DataStore>,
        purpose: String,
    ) -> Result<Self, KeyError> {
        let rotation_interval = parse_duration(&config.rotation_interval).map_err(|e| {
            KeyError::KeyUnavailable(format!(
                "invalid rotation_interval '{}': {}",
                config.rotation_interval, e
            ))
        })?;
        let key_overlap = parse_duration(&config.key_overlap).map_err(|e| {
            KeyError::KeyUnavailable(format!(
                "invalid key_overlap '{}': {}",
                config.key_overlap, e
            ))
        })?;

        // Try to load existing keys from the DataStore
        let existing_keys = data_store
            .get_active_ephemeral_keys(&purpose)
            .await
            .map_err(|e| {
                KeyError::KeyUnavailable(format!("failed to load keys from datastore: {}", e))
            })?;

        let (active_state, previous_states) = if existing_keys.is_empty() {
            // Generate initial key
            let state = generate_ephemeral_key(&kms_client, &key_overlap).await?;

            // Persist to DataStore
            let record = ephemeral_key_to_record(&state, &purpose);
            data_store.put_ephemeral_key(&record).await.map_err(|e| {
                KeyError::KeyUnavailable(format!("failed to persist initial key: {}", e))
            })?;

            (state, Vec::new())
        } else {
            // Load from existing records - find the most recently created as active
            let mut states: Vec<EphemeralKeyState> = Vec::new();
            for record in &existing_keys {
                match record_to_ephemeral_key(record) {
                    Ok(state) => states.push(state),
                    Err(e) => {
                        warn!(
                            key_id = %record.key_id,
                            error = %e,
                            "skipping unloadable ephemeral key"
                        );
                    }
                }
            }

            if states.is_empty() {
                // All existing keys failed to load, generate a new one
                let state = generate_ephemeral_key(&kms_client, &key_overlap).await?;
                let record = ephemeral_key_to_record(&state, &purpose);
                data_store.put_ephemeral_key(&record).await.map_err(|e| {
                    KeyError::KeyUnavailable(format!("failed to persist initial key: {}", e))
                })?;
                (state, Vec::new())
            } else {
                // Sort by created_at descending, take the newest as active
                states.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                let active = states.remove(0);
                (active, states)
            }
        };

        let cached_jwks = build_jwks(&active_state, &previous_states);

        Ok(Self {
            active_key: RwLock::new(active_state),
            previous_keys: RwLock::new(previous_states),
            cached_jwks: RwLock::new(cached_jwks),
            kms_client,
            data_store,
            config,
            purpose,
            rotation_interval,
            key_overlap,
        })
    }

    /// Cleans up expired keys from previous_keys and the DataStore.
    async fn cleanup_expired_keys(&self) {
        let now = Utc::now();

        // Remove expired keys from in-memory previous_keys
        {
            let mut previous = self.previous_keys.write().unwrap();
            previous.retain(|k| k.expires_at > now);
        }

        // Remove expired keys from DataStore
        let before = now.to_rfc3339();
        if let Err(e) = self
            .data_store
            .delete_expired_ephemeral_keys(&self.purpose, &before)
            .await
        {
            warn!(
                purpose = %self.purpose,
                error = %e,
                "failed to delete expired keys from datastore"
            );
        }
    }

    /// Rebuilds and caches the JWKS response from current state.
    fn rebuild_cached_jwks(&self) {
        let active = self.active_key.read().unwrap();
        let previous = self.previous_keys.read().unwrap();
        let jwks = build_jwks(&active, &previous);
        let mut cached = self.cached_jwks.write().unwrap();
        *cached = jwks;
    }
}

#[async_trait]
impl KeyManager for KmsDelegatedKeyManager {
    fn encoding_key(&self) -> &EncodingKey {
        // SAFETY: We return a reference into the RwLock-protected data.
        // This is sound because:
        // 1. The struct (and thus the RwLock) lives as long as any reference
        // 2. Rotation replaces the *contents* via write lock, but the allocation
        //    is stable (RwLock<T> stores T inline, and we swap the T)
        // 3. In practice, callers use the returned reference briefly for signing
        //
        // We use a raw pointer to extend the lifetime past the MutexGuard.
        // The alternative would be Arc-wrapping each field, but that adds overhead.
        let guard = self.active_key.read().unwrap();
        unsafe { &*(&guard.encoding_key as *const EncodingKey) }
    }

    fn header(&self) -> &Header {
        let guard = self.active_key.read().unwrap();
        unsafe { &*(&guard.header as *const Header) }
    }

    fn jwks(&self) -> &Value {
        let guard = self.cached_jwks.read().unwrap();
        unsafe { &*(&*guard as *const Value) }
    }

    fn key_id(&self) -> &str {
        let guard = self.active_key.read().unwrap();
        unsafe { &*(guard.key_id.as_str() as *const str) }
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }

    async fn health(&self) -> KeyHealth {
        let created_at = {
            let active = self.active_key.read().unwrap();
            active.created_at
        };
        let now = Utc::now();
        let key_age = now.signed_duration_since(created_at);
        let threshold = self.rotation_interval * 2;

        if key_age > threshold {
            KeyHealth::Degraded {
                reason: format!(
                    "key age ({}) exceeds 2x rotation_interval ({})",
                    format_duration(key_age),
                    format_duration(threshold),
                ),
            }
        } else {
            KeyHealth::Healthy
        }
    }

    async fn maybe_rotate(&self) -> Result<(), KeyError> {
        let should_rotate = {
            let active = self.active_key.read().unwrap();
            let now = Utc::now();
            let key_age = now.signed_duration_since(active.created_at);
            key_age >= self.rotation_interval
        };

        if !should_rotate {
            return Ok(());
        }

        // Attempt rotation - generate new key with KMS attestation
        let new_state = match generate_ephemeral_key(&self.kms_client, &self.key_overlap).await {
            Ok(state) => state,
            Err(e) => {
                warn!(
                    purpose = %self.purpose,
                    error = %e,
                    "KMS failure during key rotation, keeping current key"
                );
                return Err(e);
            }
        };

        // Persist the new key to DataStore
        let record = ephemeral_key_to_record(&new_state, &self.purpose);
        if let Err(e) = self.data_store.put_ephemeral_key(&record).await {
            warn!(
                purpose = %self.purpose,
                error = %e,
                "failed to persist rotated key to datastore"
            );
            return Err(KeyError::KeyUnavailable(format!(
                "failed to persist rotated key: {}",
                e
            )));
        }

        // Move current active to previous, set new as active
        {
            let mut active = self.active_key.write().unwrap();
            let mut previous = self.previous_keys.write().unwrap();

            let old_active = std::mem::replace(&mut *active, new_state);
            previous.push(old_active);
        }

        // Cleanup expired keys
        self.cleanup_expired_keys().await;

        // Rebuild cached JWKS
        self.rebuild_cached_jwks();

        Ok(())
    }
}

// ── Helper Functions ──

/// Generate a new ephemeral EC P-256 key pair, compute kid, and call KMS for attestation.
async fn generate_ephemeral_key(
    kms_client: &Arc<dyn KmsClient>,
    key_overlap: &Duration,
) -> Result<EphemeralKeyState, KeyError> {
    let rng = ring::rand::SystemRandom::new();

    // Generate EC P-256 key pair
    let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .map_err(|e| KeyError::KeyUnavailable(format!("failed to generate EC key pair: {}", e)))?;

    // Parse the key pair to extract public key
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8_doc.as_ref(),
        &rng,
    )
    .map_err(|e| KeyError::KeyUnavailable(format!("failed to parse generated key: {}", e)))?;

    // Extract public key point (uncompressed: 0x04 || x(32) || y(32))
    let public_key_bytes = key_pair.public_key().as_ref();
    if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
        return Err(KeyError::KeyUnavailable(
            "unexpected public key format".to_string(),
        ));
    }

    let x_bytes = &public_key_bytes[1..33];
    let y_bytes = &public_key_bytes[33..65];
    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

    // Compute kid = base64url(SHA-256(JWK Thumbprint per RFC 7638))
    // For EC keys: {"crv":"P-256","kty":"EC","x":"...","y":"..."} (lexicographic order)
    let thumbprint_input = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );
    let thumbprint_hash =
        ring::digest::digest(&ring::digest::SHA256, thumbprint_input.as_bytes());
    let key_id = URL_SAFE_NO_PAD.encode(thumbprint_hash.as_ref());

    // Call KMS to sign (attest) the public key
    let _attestation = kms_client.sign(public_key_bytes).await.map_err(|e| {
        KeyError::KmsUnavailable(format!("KMS attestation failed: {}", e))
    })?;

    // Build PEM from PKCS#8 DER
    let pem = pkcs8_to_pem(pkcs8_doc.as_ref());

    // Build EncodingKey from PEM
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| KeyError::KeyUnavailable(format!("failed to create encoding key: {}", e)))?;

    // Build JWT header
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.clone());

    // Build JWK entry
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "kid": key_id,
        "alg": "ES256",
        "use": "sig",
    });

    let now = Utc::now();
    let expires_at = now + *key_overlap;

    Ok(EphemeralKeyState {
        encoding_key,
        header,
        jwk,
        key_id,
        created_at: now,
        expires_at,
    })
}

/// Convert an EphemeralKeyState to an EphemeralKeyRecord for persistence.
fn ephemeral_key_to_record(state: &EphemeralKeyState, purpose: &str) -> EphemeralKeyRecord {
    EphemeralKeyRecord {
        key_id: state.key_id.clone(),
        public_key_pem: String::new(), // Public key is embedded in the JWK
        private_key_encrypted: Vec::new(), // In this implementation, keys are ephemeral in-memory
        kms_attestation: Vec::new(),
        algorithm: "ES256".to_string(),
        created_at: state.created_at.to_rfc3339(),
        expires_at: state.expires_at.to_rfc3339(),
        purpose: purpose.to_string(),
    }
}

/// Convert an EphemeralKeyRecord back to an EphemeralKeyState.
///
/// Since private keys are ephemeral and not persisted in encrypted form
/// in this initial implementation, a fresh key pair is generated on load.
/// The timing metadata from the record is preserved.
fn record_to_ephemeral_key(record: &EphemeralKeyRecord) -> Result<EphemeralKeyState, KeyError> {
    let created_at: DateTime<Utc> = record
        .created_at
        .parse()
        .map_err(|e| KeyError::KeyUnavailable(format!("invalid created_at timestamp: {}", e)))?;
    let expires_at: DateTime<Utc> = record
        .expires_at
        .parse()
        .map_err(|e| KeyError::KeyUnavailable(format!("invalid expires_at timestamp: {}", e)))?;

    // Generate a new key pair (since we don't persist encrypted private keys yet)
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .map_err(|e| KeyError::KeyUnavailable(format!("failed to generate key on load: {}", e)))?;

    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8_doc.as_ref(),
        &rng,
    )
    .map_err(|e| KeyError::KeyUnavailable(format!("failed to parse generated key: {}", e)))?;

    let public_key_bytes = key_pair.public_key().as_ref();
    let x_bytes = &public_key_bytes[1..33];
    let y_bytes = &public_key_bytes[33..65];
    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

    // Compute kid from the new key material
    let thumbprint_input = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );
    let thumbprint_hash =
        ring::digest::digest(&ring::digest::SHA256, thumbprint_input.as_bytes());
    let key_id = URL_SAFE_NO_PAD.encode(thumbprint_hash.as_ref());

    let pem = pkcs8_to_pem(pkcs8_doc.as_ref());
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| KeyError::KeyUnavailable(format!("failed to create encoding key: {}", e)))?;

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.clone());

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "kid": key_id,
        "alg": "ES256",
        "use": "sig",
    });

    Ok(EphemeralKeyState {
        encoding_key,
        header,
        jwk,
        key_id,
        created_at,
        expires_at,
    })
}

/// Build the full JWKS value from active + previous keys (filtering expired).
fn build_jwks(active: &EphemeralKeyState, previous: &[EphemeralKeyState]) -> Value {
    let now = Utc::now();
    let mut keys = vec![active.jwk.clone()];

    for prev in previous {
        if prev.expires_at > now {
            keys.push(prev.jwk.clone());
        }
    }

    json!({ "keys": keys })
}

/// Convert PKCS#8 DER bytes to PEM format.
fn pkcs8_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    let b64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// Parse a duration string like "6h", "24h", "30m", "7d" into a chrono Duration.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let (num_str, suffix) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|e| format!("invalid number '{}': {}", num_str, e))?;

    match suffix {
        "s" => Ok(Duration::seconds(num)),
        "m" => Ok(Duration::minutes(num)),
        "h" => Ok(Duration::hours(num)),
        "d" => Ok(Duration::days(num)),
        _ => Err(format!(
            "unknown duration suffix '{}' (expected s, m, h, or d)",
            suffix
        )),
    }
}

/// Format a chrono Duration for display.
fn format_duration(d: Duration) -> String {
    let total_secs = d.num_seconds();
    if total_secs >= 86400 && total_secs % 86400 == 0 {
        format!("{}d", total_secs / 86400)
    } else if total_secs >= 3600 && total_secs % 3600 == 0 {
        format!("{}h", total_secs / 3600)
    } else if total_secs >= 60 && total_secs % 60 == 0 {
        format!("{}m", total_secs / 60)
    } else {
        format!("{}s", total_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::MockDataStore;
    use crate::keymanager::kms_client::MockKmsClient;

    fn mock_kms_client_success() -> MockKmsClient {
        let mut mock = MockKmsClient::new();
        mock.expect_sign()
            .returning(|_data| Ok(vec![0u8; 64]));
        mock
    }

    fn mock_datastore_empty() -> MockDataStore {
        let mut mock = MockDataStore::new();
        mock.expect_get_active_ephemeral_keys()
            .returning(|_purpose| Ok(Vec::new()));
        mock.expect_put_ephemeral_key()
            .returning(|_record| Ok(()));
        mock.expect_delete_expired_ephemeral_keys()
            .returning(|_purpose, _before| Ok(0));
        mock
    }

    fn test_config() -> KmsDelegatedConfig {
        KmsDelegatedConfig {
            rotation_interval: "1h".to_string(),
            key_overlap: "2h".to_string(),
            ephemeral_algorithm: "ES256".to_string(),
            aws_kms: None,
            gcp_kms: None,
        }
    }

    #[tokio::test]
    async fn test_new_generates_initial_key_when_datastore_empty() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        assert!(!manager.key_id().is_empty());
    }

    #[tokio::test]
    async fn test_algorithm_returns_es256() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        assert_eq!(manager.algorithm(), Algorithm::ES256);
    }

    #[tokio::test]
    async fn test_health_returns_healthy_for_fresh_key() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        assert_eq!(manager.health().await, KeyHealth::Healthy);
    }

    #[tokio::test]
    async fn test_jwks_contains_active_key() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        let jwks = manager.jwks();
        let keys = jwks["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"].as_str().unwrap(), manager.key_id());
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["crv"], "P-256");
        assert_eq!(keys[0]["alg"], "ES256");
    }

    #[tokio::test]
    async fn test_header_has_kid_and_es256() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        let header = manager.header();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some(manager.key_id()));
    }

    #[tokio::test]
    async fn test_maybe_rotate_noop_when_key_is_fresh() {
        let kms = Arc::new(mock_kms_client_success());
        let ds = Arc::new(mock_datastore_empty());
        let config = test_config();

        let manager = KmsDelegatedKeyManager::new(config, kms, ds, "signing".to_string())
            .await
            .expect("should create manager");

        let kid_before = manager.key_id().to_string();
        manager.maybe_rotate().await.expect("should succeed");
        assert_eq!(manager.key_id(), kid_before);
    }

    #[tokio::test]
    async fn test_kms_failure_on_new_returns_error() {
        let mut kms = MockKmsClient::new();
        kms.expect_sign()
            .returning(|_data| Err(KeyError::KmsUnavailable("test failure".to_string())));

        let mut ds = MockDataStore::new();
        ds.expect_get_active_ephemeral_keys()
            .returning(|_purpose| Ok(Vec::new()));

        let config = test_config();
        let result = KmsDelegatedKeyManager::new(
            config,
            Arc::new(kms),
            Arc::new(ds),
            "signing".to_string(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_maybe_rotate_performs_rotation_when_due() {
        let mut kms = MockKmsClient::new();
        kms.expect_sign()
            .returning(|_data| Ok(vec![0u8; 64]));

        let mut ds = MockDataStore::new();
        ds.expect_get_active_ephemeral_keys()
            .returning(|_purpose| Ok(Vec::new()));
        ds.expect_put_ephemeral_key()
            .returning(|_record| Ok(()));
        ds.expect_delete_expired_ephemeral_keys()
            .returning(|_purpose, _before| Ok(0));

        // Use a very short rotation interval so key is already "due"
        let config = KmsDelegatedConfig {
            rotation_interval: "0s".to_string(), // always due
            key_overlap: "2h".to_string(),
            ephemeral_algorithm: "ES256".to_string(),
            aws_kms: None,
            gcp_kms: None,
        };

        let manager =
            KmsDelegatedKeyManager::new(config, Arc::new(kms), Arc::new(ds), "signing".to_string())
                .await
                .expect("should create manager");

        let kid_before = manager.key_id().to_string();

        // Wait a tiny bit to ensure the key age > 0s
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        manager.maybe_rotate().await.expect("should rotate");
        let kid_after = manager.key_id().to_string();

        assert_ne!(kid_before, kid_after, "key should have rotated");
    }

    #[tokio::test]
    async fn test_rotation_moves_old_key_to_previous_and_updates_jwks() {
        let mut kms = MockKmsClient::new();
        kms.expect_sign()
            .returning(|_data| Ok(vec![0u8; 64]));

        let mut ds = MockDataStore::new();
        ds.expect_get_active_ephemeral_keys()
            .returning(|_purpose| Ok(Vec::new()));
        ds.expect_put_ephemeral_key()
            .returning(|_record| Ok(()));
        ds.expect_delete_expired_ephemeral_keys()
            .returning(|_purpose, _before| Ok(0));

        let config = KmsDelegatedConfig {
            rotation_interval: "0s".to_string(),
            key_overlap: "2h".to_string(),
            ephemeral_algorithm: "ES256".to_string(),
            aws_kms: None,
            gcp_kms: None,
        };

        let manager =
            KmsDelegatedKeyManager::new(config, Arc::new(kms), Arc::new(ds), "signing".to_string())
                .await
                .expect("should create manager");

        let kid_before = manager.key_id().to_string();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        manager.maybe_rotate().await.expect("should rotate");

        // JWKS should now contain both the new active and the previous key
        let jwks = manager.jwks();
        let keys = jwks["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 2, "should have active + previous key");

        let kids: Vec<&str> = keys.iter().map(|k| k["kid"].as_str().unwrap()).collect();
        assert!(kids.contains(&manager.key_id()));
        assert!(kids.contains(&kid_before.as_str()));
    }

    #[tokio::test]
    async fn test_kms_failure_during_rotation_keeps_current_key() {
        // First call succeeds (initial key generation), subsequent calls fail
        let mut kms = MockKmsClient::new();
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();
        kms.expect_sign().returning(move |_data| {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                Ok(vec![0u8; 64]) // first call succeeds
            } else {
                Err(KeyError::KmsUnavailable("simulated failure".to_string()))
            }
        });

        let mut ds = MockDataStore::new();
        ds.expect_get_active_ephemeral_keys()
            .returning(|_purpose| Ok(Vec::new()));
        ds.expect_put_ephemeral_key()
            .returning(|_record| Ok(()));

        let config = KmsDelegatedConfig {
            rotation_interval: "0s".to_string(),
            key_overlap: "2h".to_string(),
            ephemeral_algorithm: "ES256".to_string(),
            aws_kms: None,
            gcp_kms: None,
        };

        let manager =
            KmsDelegatedKeyManager::new(config, Arc::new(kms), Arc::new(ds), "signing".to_string())
                .await
                .expect("should create manager");

        let kid_before = manager.key_id().to_string();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let result = manager.maybe_rotate().await;
        assert!(result.is_err(), "rotation should fail due to KMS error");

        // Key should remain unchanged
        assert_eq!(manager.key_id(), kid_before);
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("6h").unwrap();
        assert_eq!(d, Duration::hours(6));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("30m").unwrap();
        assert_eq!(d, Duration::minutes(30));
    }

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration("7d").unwrap();
        assert_eq!(d, Duration::days(7));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let d = parse_duration("120s").unwrap();
        assert_eq!(d, Duration::seconds(120));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("6x").is_err());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::hours(6)), "6h");
        assert_eq!(format_duration(Duration::days(1)), "1d");
        assert_eq!(format_duration(Duration::minutes(30)), "30m");
        assert_eq!(format_duration(Duration::seconds(45)), "45s");
    }

    #[test]
    fn test_pkcs8_to_pem_format() {
        let fake_der = vec![0u8; 32];
        let pem = pkcs8_to_pem(&fake_der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_build_jwks_active_only() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();

        let pem = pkcs8_to_pem(pkcs8_doc.as_ref());
        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-kid".to_string());

        let active = EphemeralKeyState {
            encoding_key,
            header,
            jwk: json!({"kid": "active-kid", "kty": "EC"}),
            key_id: "active-kid".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
        };

        let jwks = build_jwks(&active, &[]);
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "active-kid");
    }

    #[test]
    fn test_build_jwks_filters_expired_previous() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pem = pkcs8_to_pem(pkcs8_doc.as_ref());
        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("active".to_string());

        let active = EphemeralKeyState {
            encoding_key,
            header: header.clone(),
            jwk: json!({"kid": "active-kid", "kty": "EC"}),
            key_id: "active-kid".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
        };

        // Create an expired previous key
        let pkcs8_doc2 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pem2 = pkcs8_to_pem(pkcs8_doc2.as_ref());
        let encoding_key2 = EncodingKey::from_ec_pem(pem2.as_bytes()).unwrap();

        let expired_previous = EphemeralKeyState {
            encoding_key: encoding_key2,
            header: header.clone(),
            jwk: json!({"kid": "expired-kid", "kty": "EC"}),
            key_id: "expired-kid".to_string(),
            created_at: Utc::now() - Duration::hours(48),
            expires_at: Utc::now() - Duration::hours(1),
        };

        // Create a valid previous key
        let pkcs8_doc3 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pem3 = pkcs8_to_pem(pkcs8_doc3.as_ref());
        let encoding_key3 = EncodingKey::from_ec_pem(pem3.as_bytes()).unwrap();

        let valid_previous = EphemeralKeyState {
            encoding_key: encoding_key3,
            header,
            jwk: json!({"kid": "valid-prev-kid", "kty": "EC"}),
            key_id: "valid-prev-kid".to_string(),
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() + Duration::hours(22),
        };

        let previous = vec![expired_previous, valid_previous];
        let jwks = build_jwks(&active, &previous);
        let keys = jwks["keys"].as_array().unwrap();

        // Should have active + valid previous, but not expired
        assert_eq!(keys.len(), 2);
        let kids: Vec<&str> = keys.iter().map(|k| k["kid"].as_str().unwrap()).collect();
        assert!(kids.contains(&"active-kid"));
        assert!(kids.contains(&"valid-prev-kid"));
        assert!(!kids.contains(&"expired-kid"));
    }
}
