//! KMS client trait and implementations for cryptographic signing via cloud KMS services.

use async_trait::async_trait;

use super::KeyError;

/// Trait for interacting with a cloud KMS service for signing and verification.
///
/// Implementations wrap a specific cloud provider's KMS SDK (e.g., AWS KMS, GCP Cloud KMS).
/// The trait is kept minimal: sign raw data and verify a signature.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait KmsClient: Send + Sync {
    /// Sign the given data with the KMS key. Returns the signature bytes.
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// Verify a signature against the KMS public key.
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, KeyError>;
}

/// AWS KMS client implementation using `aws-sdk-kms`.
///
/// Uses the ECDSA_SHA_256 signing algorithm with DIGEST message type,
/// meaning callers should pass a SHA-256 digest as `data`.
pub struct AwsKmsClient {
    /// The AWS KMS SDK client.
    client: aws_sdk_kms::Client,
    /// The ARN of the KMS key to use for signing/verification.
    key_arn: String,
}

impl AwsKmsClient {
    /// Create a new `AwsKmsClient` from an AWS SDK config and key ARN.
    pub fn new(sdk_config: &aws_config::SdkConfig, key_arn: String) -> Self {
        let client = aws_sdk_kms::Client::new(sdk_config);
        Self { client, key_arn }
    }
}

#[async_trait]
impl KmsClient for AwsKmsClient {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        let response = self
            .client
            .sign()
            .key_id(&self.key_arn)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .message(aws_sdk_kms::primitives::Blob::new(data))
            .send()
            .await
            .map_err(|e| KeyError::KmsUnavailable(format!("AWS KMS sign failed: {}", e)))?;

        let signature = response
            .signature()
            .ok_or_else(|| KeyError::SigningFailed("AWS KMS returned no signature".to_string()))?;

        Ok(signature.as_ref().to_vec())
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, KeyError> {
        let response = self
            .client
            .verify()
            .key_id(&self.key_arn)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .message(aws_sdk_kms::primitives::Blob::new(data))
            .signature(aws_sdk_kms::primitives::Blob::new(signature))
            .send()
            .await
            .map_err(|e| KeyError::KmsUnavailable(format!("AWS KMS verify failed: {}", e)))?;

        Ok(response.signature_valid())
    }
}

/// GCP Cloud KMS client (placeholder/stub for initial implementation).
///
/// This struct holds the configuration needed for a future full implementation
/// using the GCP Cloud KMS API.
pub struct GcpKmsClient {
    /// The full resource name of the GCP KMS key version.
    #[allow(dead_code)]
    key_name: String,
}

impl GcpKmsClient {
    /// Create a new `GcpKmsClient` with the given key resource name.
    pub fn new(key_name: String) -> Self {
        Self { key_name }
    }
}

#[async_trait]
impl KmsClient for GcpKmsClient {
    async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, KeyError> {
        Err(KeyError::KmsUnavailable(
            "GCP KMS not yet implemented".to_string(),
        ))
    }

    async fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, KeyError> {
        Err(KeyError::KmsUnavailable(
            "GCP KMS not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gcp_kms_client_sign_returns_unavailable() {
        let client = GcpKmsClient::new("projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".to_string());
        let result = client.sign(b"test data").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            KeyError::KmsUnavailable(msg) => {
                assert_eq!(msg, "GCP KMS not yet implemented");
            }
            other => panic!("Expected KmsUnavailable, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_gcp_kms_client_verify_returns_unavailable() {
        let client = GcpKmsClient::new("projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".to_string());
        let result = client.verify(b"test data", b"signature").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            KeyError::KmsUnavailable(msg) => {
                assert_eq!(msg, "GCP KMS not yet implemented");
            }
            other => panic!("Expected KmsUnavailable, got: {:?}", other),
        }
    }
}
