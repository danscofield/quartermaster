// OIDC discovery document builder

use serde::Serialize;

/// OpenID Connect discovery document for Quartermaster.
///
/// Serves at `GET /.well-known/openid-configuration` and provides
/// cloud provider IAM systems with the information needed to verify
/// Quartermaster-issued JWTs.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    /// The issuer URL matching Quartermaster's configured issuer.
    pub issuer: String,

    /// The URL of the JWKS endpoint (issuer + "/jwks.json").
    pub jwks_uri: String,

    /// Supported response types.
    pub response_types_supported: Vec<String>,

    /// Supported subject types.
    pub subject_types_supported: Vec<String>,

    /// Supported signing algorithms for ID tokens.
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// Supported claims in issued tokens.
    pub claims_supported: Vec<String>,
}

impl DiscoveryDocument {
    /// Construct a new OIDC discovery document from the issuer URL and signing algorithm.
    ///
    /// The `jwks_uri` is derived by appending "/jwks.json" to the issuer.
    pub fn new(issuer: &str, algorithm: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            jwks_uri: format!("{}/jwks.json", issuer),
            response_types_supported: vec!["id_token".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![algorithm.to_string()],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "billets".to_string(),
                "jti".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document_construction() {
        let doc = DiscoveryDocument::new("https://qm.example.com", "ES256");

        assert_eq!(doc.issuer, "https://qm.example.com");
        assert_eq!(doc.jwks_uri, "https://qm.example.com/jwks.json");
        assert_eq!(doc.response_types_supported, vec!["id_token"]);
        assert_eq!(doc.subject_types_supported, vec!["public"]);
        assert_eq!(doc.id_token_signing_alg_values_supported, vec!["ES256"]);
        assert_eq!(
            doc.claims_supported,
            vec!["sub", "iss", "aud", "exp", "iat", "billets", "jti"]
        );
    }

    #[test]
    fn test_discovery_document_serializes_to_json() {
        let doc = DiscoveryDocument::new("https://qm.example.com", "ES256");
        let json = serde_json::to_value(&doc).unwrap();

        assert_eq!(json["issuer"], "https://qm.example.com");
        assert_eq!(json["jwks_uri"], "https://qm.example.com/jwks.json");
        assert_eq!(json["response_types_supported"], serde_json::json!(["id_token"]));
        assert_eq!(json["subject_types_supported"], serde_json::json!(["public"]));
        assert_eq!(
            json["id_token_signing_alg_values_supported"],
            serde_json::json!(["ES256"])
        );
        assert_eq!(
            json["claims_supported"],
            serde_json::json!(["sub", "iss", "aud", "exp", "iat", "billets", "jti"])
        );
    }

    #[test]
    fn test_discovery_document_with_different_algorithm() {
        let doc = DiscoveryDocument::new("https://auth.prod.example.com", "RS256");

        assert_eq!(doc.issuer, "https://auth.prod.example.com");
        assert_eq!(doc.jwks_uri, "https://auth.prod.example.com/jwks.json");
        assert_eq!(doc.id_token_signing_alg_values_supported, vec!["RS256"]);
    }

    #[test]
    fn test_discovery_document_jwks_uri_derived_from_issuer() {
        let doc = DiscoveryDocument::new("https://issuer.test", "ES384");
        assert_eq!(doc.jwks_uri, "https://issuer.test/jwks.json");
    }
}
