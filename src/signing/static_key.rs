//! Static key implementation for ES256 signing.
//!
//! Loads an EC P-256 private key from a PEM file, extracts public key components,
//! computes a key ID per RFC 7638 (JWK Thumbprint), and provides JWKS for publication.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::KeyPair;
use serde_json::{json, Value};

use super::SigningManager;

/// StaticKeyManager holds a pre-loaded ES256 signing key and its associated metadata.
pub struct StaticKeyManager {
    encoding_key: EncodingKey,
    header: Header,
    jwks: Value,
    key_id: String,
}

impl StaticKeyManager {
    /// Creates a new StaticKeyManager by loading an EC P-256 private key from a PEM file.
    ///
    /// The PEM file should contain an EC private key (SEC1 or PKCS#8 format).
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self, StaticKeyError> {
        let pem_bytes = std::fs::read(path)
            .map_err(|e| StaticKeyError::IoError(format!("failed to read key file: {e}")))?;

        Self::from_pem(&pem_bytes)
    }

    /// Creates a new StaticKeyManager from PEM-encoded key bytes.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, StaticKeyError> {
        let pem_str = std::str::from_utf8(pem_bytes)
            .map_err(|e| StaticKeyError::InvalidKey(format!("PEM is not valid UTF-8: {e}")))?;

        // Parse the PEM to get DER bytes for ring
        let der_bytes = parse_ec_private_key_pem(pem_str)?;

        // Use ring to parse the key and extract the public key point
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &der_bytes,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|e| StaticKeyError::InvalidKey(format!("failed to parse EC key: {e}")))?;

        // The public key is an uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
        let public_key_bytes = key_pair.public_key().as_ref();
        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            return Err(StaticKeyError::InvalidKey(
                "unexpected public key format (expected uncompressed P-256 point)".to_string(),
            ));
        }

        let x_bytes = &public_key_bytes[1..33];
        let y_bytes = &public_key_bytes[33..65];

        let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
        let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

        // Compute key ID as base64url(SHA-256(JWK Thumbprint)) per RFC 7638
        // For EC keys, the thumbprint input is: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
        // Members MUST be in lexicographic order per RFC 7638 Section 3.2
        let thumbprint_input = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            x_b64, y_b64
        );

        let thumbprint_hash = ring::digest::digest(
            &ring::digest::SHA256,
            thumbprint_input.as_bytes(),
        );
        let key_id = URL_SAFE_NO_PAD.encode(thumbprint_hash.as_ref());

        // Build JWKS
        let jwks = json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x_b64,
                    "y": y_b64,
                    "kid": key_id,
                    "alg": "ES256",
                    "use": "sig",
                }
            ]
        });

        // Build JWT header
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.clone());

        // Build encoding key from PEM
        let encoding_key = EncodingKey::from_ec_pem(pem_bytes)
            .map_err(|e| StaticKeyError::InvalidKey(format!("failed to create encoding key: {e}")))?;

        Ok(Self {
            encoding_key,
            header,
            jwks,
            key_id,
        })
    }
}

impl SigningManager for StaticKeyManager {
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
}

/// Errors that can occur when loading a static signing key.
#[derive(Debug)]
pub enum StaticKeyError {
    IoError(String),
    InvalidKey(String),
}

impl std::fmt::Display for StaticKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

impl std::error::Error for StaticKeyError {}

/// Parse an EC private key from PEM format, returning PKCS#8 DER bytes.
///
/// Supports both SEC1 (EC PRIVATE KEY) and PKCS#8 (PRIVATE KEY) PEM formats.
fn parse_ec_private_key_pem(pem_str: &str) -> Result<Vec<u8>, StaticKeyError> {
    // Try PKCS#8 format first
    if let Some(der) = extract_pem_der(pem_str, "PRIVATE KEY") {
        return Ok(der);
    }

    // Try SEC1 format - need to wrap in PKCS#8 for ring
    if let Some(sec1_der) = extract_pem_der(pem_str, "EC PRIVATE KEY") {
        let pkcs8_der = wrap_sec1_in_pkcs8(&sec1_der)?;
        return Ok(pkcs8_der);
    }

    Err(StaticKeyError::InvalidKey(
        "PEM does not contain a recognized EC private key (expected PRIVATE KEY or EC PRIVATE KEY header)".to_string(),
    ))
}

/// Extract DER bytes from a PEM block with the given label.
fn extract_pem_der(pem_str: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {}-----", label);
    let end = format!("-----END {}-----", label);

    let start_idx = pem_str.find(&begin)?;
    let content_start = start_idx + begin.len();
    let end_idx = pem_str[content_start..].find(&end)?;
    let base64_content = &pem_str[content_start..content_start + end_idx];

    // Remove whitespace and decode base64
    let cleaned: String = base64_content.chars().filter(|c| !c.is_whitespace()).collect();

    use base64::engine::general_purpose::STANDARD;
    STANDARD.decode(&cleaned).ok()
}

/// Wrap a SEC1 EC private key in PKCS#8 format for P-256.
///
/// PKCS#8 structure:
///   SEQUENCE {
///     INTEGER 0 (version)
///     SEQUENCE {
///       OID 1.2.840.10045.2.1 (ecPublicKey)
///       OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
///     }
///     OCTET STRING { <SEC1 key> }
///   }
fn wrap_sec1_in_pkcs8(sec1_der: &[u8]) -> Result<Vec<u8>, StaticKeyError> {
    // PKCS#8 header for EC P-256 keys (fixed prefix)
    // This is the ASN.1 encoding up to and including the OCTET STRING tag+length
    let ec_p256_pkcs8_prefix: &[u8] = &[
        0x30, 0x81, // SEQUENCE, length placeholder (we'll fix this)
        0x87, // length of inner content (we'll fix this too)
        // Version
        0x02, 0x01, 0x00, // INTEGER 0
        // AlgorithmIdentifier
        0x30, 0x13, // SEQUENCE (19 bytes)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
        // OCTET STRING wrapping the SEC1 key
        0x04, // tag
    ];

    // Build the PKCS#8 structure properly
    // AlgorithmIdentifier: fixed 21 bytes (0x30 0x13 ...)
    let algo_id: &[u8] = &[
        0x30, 0x13, // SEQUENCE (19 bytes)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
    ];

    let _ = ec_p256_pkcs8_prefix; // suppress unused warning

    // version: INTEGER 0
    let version: &[u8] = &[0x02, 0x01, 0x00];

    // OCTET STRING containing the SEC1 key
    let mut octet_string = Vec::new();
    octet_string.push(0x04); // OCTET STRING tag
    encode_asn1_length(sec1_der.len(), &mut octet_string);
    octet_string.extend_from_slice(sec1_der);

    // Inner SEQUENCE content
    let inner_len = version.len() + algo_id.len() + octet_string.len();

    // Outer SEQUENCE
    let mut pkcs8 = Vec::new();
    pkcs8.push(0x30); // SEQUENCE tag
    encode_asn1_length(inner_len, &mut pkcs8);
    pkcs8.extend_from_slice(version);
    pkcs8.extend_from_slice(algo_id);
    pkcs8.extend_from_slice(&octet_string);

    Ok(pkcs8)
}

/// Encode an ASN.1 DER length.
fn encode_asn1_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a test EC P-256 key pair and return the PKCS#8 PEM.
    fn generate_test_ec_key_pem() -> Vec<u8> {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("failed to generate test key");

        // Encode as PEM
        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_doc.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem.into_bytes()
    }

    #[test]
    fn test_static_key_manager_from_pem() {
        let pem = generate_test_ec_key_pem();
        let manager = StaticKeyManager::from_pem(&pem).expect("should load key");

        // Key ID should be non-empty base64url
        assert!(!manager.key_id().is_empty());
        // Should be valid base64url
        URL_SAFE_NO_PAD
            .decode(manager.key_id())
            .expect("key_id should be valid base64url");

        // Header should have ES256 and kid
        assert_eq!(manager.header().alg, Algorithm::ES256);
        assert_eq!(manager.header().kid.as_deref(), Some(manager.key_id()));

        // JWKS should have the expected structure
        let jwks = manager.jwks();
        let keys = jwks["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], manager.key_id());
        assert!(key["x"].is_string());
        assert!(key["y"].is_string());
    }

    #[test]
    fn test_key_id_is_deterministic() {
        let pem = generate_test_ec_key_pem();
        let manager1 = StaticKeyManager::from_pem(&pem).expect("should load key");
        let manager2 = StaticKeyManager::from_pem(&pem).expect("should load key");

        assert_eq!(manager1.key_id(), manager2.key_id());
    }

    #[test]
    fn test_different_keys_produce_different_ids() {
        let pem1 = generate_test_ec_key_pem();
        let pem2 = generate_test_ec_key_pem();

        let manager1 = StaticKeyManager::from_pem(&pem1).expect("should load key");
        let manager2 = StaticKeyManager::from_pem(&pem2).expect("should load key");

        assert_ne!(manager1.key_id(), manager2.key_id());
    }

    #[test]
    fn test_invalid_pem_returns_error() {
        let result = StaticKeyManager::from_pem(b"not a pem file");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwks_x_y_are_32_byte_base64url() {
        let pem = generate_test_ec_key_pem();
        let manager = StaticKeyManager::from_pem(&pem).expect("should load key");

        let key = &manager.jwks()["keys"][0];
        let x = URL_SAFE_NO_PAD
            .decode(key["x"].as_str().unwrap())
            .expect("x should be valid base64url");
        let y = URL_SAFE_NO_PAD
            .decode(key["y"].as_str().unwrap())
            .expect("y should be valid base64url");

        assert_eq!(x.len(), 32, "x coordinate should be 32 bytes");
        assert_eq!(y.len(), 32, "y coordinate should be 32 bytes");
    }

    #[test]
    fn test_key_id_is_sha256_base64url() {
        let pem = generate_test_ec_key_pem();
        let manager = StaticKeyManager::from_pem(&pem).expect("should load key");

        let decoded = URL_SAFE_NO_PAD
            .decode(manager.key_id())
            .expect("key_id should be valid base64url");
        assert_eq!(decoded.len(), 32, "key_id should be SHA-256 (32 bytes)");
    }
}
