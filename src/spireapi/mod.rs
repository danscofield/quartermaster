// SPIRE Server API client

use std::fmt;

/// RegistrationEntry represents a SPIRE registration entry with its selectors.
#[derive(Debug, Clone)]
pub struct RegistrationEntry {
    pub spiffe_id: String,
    pub parent_id: Option<String>,
    pub selectors: Vec<String>, // e.g., ["k8s:ns:finance", "k8s:sa:payments-sa"]
}

/// Error types for SPIRE Server API operations.
#[derive(Debug, Clone)]
pub enum SpireApiError {
    /// Cannot reach the SPIRE server.
    ConnectionFailed(String),
    /// HTTP request failed (non-connectivity error).
    RequestFailed(String),
    /// Response could not be parsed.
    InvalidResponse(String),
}

impl fmt::Display for SpireApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpireApiError::ConnectionFailed(msg) => write!(f, "SPIRE connection failed: {}", msg),
            SpireApiError::RequestFailed(msg) => write!(f, "SPIRE request failed: {}", msg),
            SpireApiError::InvalidResponse(msg) => write!(f, "SPIRE invalid response: {}", msg),
        }
    }
}

impl std::error::Error for SpireApiError {}

/// Client trait providing access to the SPIRE Server registration API.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait SpireApiClient: Send + Sync {
    /// Retrieves the registration entry matching the given SPIFFE ID.
    /// Returns None if no entry exists.
    async fn list_entries_by_spiffe_id(
        &self,
        spiffe_id: &str,
    ) -> Result<Option<RegistrationEntry>, SpireApiError>;

    /// Checks connectivity to the SPIRE Server API.
    async fn ping(&self) -> Result<(), SpireApiError>;
}

/// HTTP-based implementation of the SPIRE Server API client.
/// Uses a simplified REST approach for querying the SPIRE Server registration API.
pub struct HttpSpireApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl HttpSpireApiClient {
    /// Creates a new HTTP SPIRE API client.
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the SPIRE Server API (e.g., "http://localhost:8081")
    pub fn new(base_url: String) -> Self {
        let client = reqwest::Client::new();
        Self { base_url, client }
    }

    /// Creates a new HTTP SPIRE API client with a custom reqwest client.
    pub fn with_client(base_url: String, client: reqwest::Client) -> Self {
        Self { base_url, client }
    }
}

/// JSON response structures for SPIRE Server REST API.
#[allow(dead_code)]
mod api_types {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct ListEntriesResponse {
        pub entries: Option<Vec<Entry>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Entry {
        pub spiffe_id: Option<SpiffeId>,
        pub parent_id: Option<SpiffeId>,
        pub selectors: Option<Vec<Selector>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct SpiffeId {
        pub trust_domain: Option<String>,
        pub path: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Selector {
        #[serde(rename = "type")]
        pub selector_type: Option<String>,
        pub value: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct HealthResponse {
        pub status: Option<String>,
    }
}

#[async_trait::async_trait]
impl SpireApiClient for HttpSpireApiClient {
    async fn list_entries_by_spiffe_id(
        &self,
        spiffe_id: &str,
    ) -> Result<Option<RegistrationEntry>, SpireApiError> {
        let url = format!("{}/v1/entries", self.base_url);

        let response = self
            .client
            .get(&url)
            .query(&[("spiffe_id", spiffe_id)])
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    SpireApiError::ConnectionFailed(e.to_string())
                } else {
                    SpireApiError::RequestFailed(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(SpireApiError::RequestFailed(format!(
                "SPIRE API returned status {}",
                response.status()
            )));
        }

        let body: api_types::ListEntriesResponse =
            response.json().await.map_err(|e| {
                SpireApiError::InvalidResponse(format!("Failed to parse response: {}", e))
            })?;

        let entries = match body.entries {
            Some(entries) if !entries.is_empty() => entries,
            _ => return Ok(None),
        };

        // Find the entry matching the requested SPIFFE ID and collect selectors
        let mut selectors = Vec::new();
        let mut parent_id = None;
        let mut found = false;

        for entry in &entries {
            if let Some(ref pid) = entry.parent_id {
                if let (Some(ref td), Some(ref path)) = (&pid.trust_domain, &pid.path) {
                    parent_id = Some(format!("spiffe://{}{}", td, path));
                }
            }
            if let Some(ref entry_selectors) = entry.selectors {
                for selector in entry_selectors {
                    if let (Some(ref sel_type), Some(ref value)) =
                        (&selector.selector_type, &selector.value)
                    {
                        selectors.push(format!("{}:{}", sel_type, value));
                    }
                }
            }
            found = true;
        }

        if !found {
            return Ok(None);
        }

        Ok(Some(RegistrationEntry {
            spiffe_id: spiffe_id.to_string(),
            parent_id,
            selectors,
        }))
    }

    async fn ping(&self) -> Result<(), SpireApiError> {
        let url = format!("{}/v1/health", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    SpireApiError::ConnectionFailed(e.to_string())
                } else {
                    SpireApiError::RequestFailed(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(SpireApiError::RequestFailed(format!(
                "SPIRE health check returned status {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_entry_creation() {
        let entry = RegistrationEntry {
                    spiffe_id: "spiffe://example.org/workload".to_string(),
                    parent_id: None,
                    selectors: vec![
                        "k8s:ns:finance".to_string(),
                        "k8s:sa:payments-sa".to_string(),
                    ],
                };

        assert_eq!(entry.spiffe_id, "spiffe://example.org/workload");
        assert_eq!(entry.selectors.len(), 2);
        assert_eq!(entry.selectors[0], "k8s:ns:finance");
        assert_eq!(entry.selectors[1], "k8s:sa:payments-sa");
    }

    #[test]
    fn test_spire_api_error_display() {
        let err = SpireApiError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "SPIRE connection failed: timeout");

        let err = SpireApiError::RequestFailed("404".to_string());
        assert_eq!(err.to_string(), "SPIRE request failed: 404");

        let err = SpireApiError::InvalidResponse("bad json".to_string());
        assert_eq!(err.to_string(), "SPIRE invalid response: bad json");
    }

    #[test]
    fn test_http_client_creation() {
        let client = HttpSpireApiClient::new("http://localhost:8081".to_string());
        assert_eq!(client.base_url, "http://localhost:8081");
    }

    #[test]
    fn test_http_client_with_custom_client() {
        let reqwest_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let client =
            HttpSpireApiClient::with_client("http://spire-server:8081".to_string(), reqwest_client);
        assert_eq!(client.base_url, "http://spire-server:8081");
    }

    #[test]
    fn test_registration_entry_clone() {
        let entry = RegistrationEntry {
                    spiffe_id: "spiffe://example.org/workload".to_string(),
                    parent_id: None,
                    selectors: vec!["k8s:ns:default".to_string()],
                };
        let cloned = entry.clone();
        assert_eq!(cloned.spiffe_id, entry.spiffe_id);
        assert_eq!(cloned.selectors, entry.selectors);
    }

    #[test]
    fn test_spire_api_error_clone() {
        let err = SpireApiError::ConnectionFailed("test".to_string());
        let cloned = err.clone();
        assert_eq!(cloned.to_string(), err.to_string());
    }
}
