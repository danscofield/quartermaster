//! Signing key manager trait and implementations.

pub mod static_key;

use jsonwebtoken::{EncodingKey, Header};
use serde_json::Value;

/// Manager manages signing keys and publishes JWKS.
pub trait SigningManager: Send + Sync {
    /// Returns the current encoding key for JWT creation.
    fn encoding_key(&self) -> &EncodingKey;

    /// Returns the JWT header (includes kid, alg).
    fn header(&self) -> &Header;

    /// Returns the current JWKS as a JSON value.
    fn jwks(&self) -> &Value;

    /// Returns the current key's ID.
    fn key_id(&self) -> &str;
}
