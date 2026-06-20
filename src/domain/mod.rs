pub mod svid;
pub mod billet;
pub mod token;
pub mod cert;
pub mod cache;
pub mod ratelimit;
pub mod audit;
pub mod admin;
pub mod identity;
pub mod bootstrap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Error codes following OAuth 2.0 conventions.
/// Each variant maps to a specific HTTP status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// HTTP 400 - The request is malformed or missing required parameters.
    InvalidRequest,
    /// HTTP 401 - The provided token is invalid, expired, or has a bad signature.
    InvalidToken,
    /// HTTP 403 - The workload does not have sufficient privileges/billets.
    InsufficientScope,
    /// HTTP 404 - The requested resource was not found.
    NotFound,
    /// HTTP 409 - A conflicting resource already exists.
    Conflict,
    /// HTTP 429 - The client has exceeded the rate limit.
    RateLimited,
    /// HTTP 503 - The service is temporarily unavailable.
    ServiceUnavailable,
}

impl ErrorCode {
    /// Returns the HTTP status code corresponding to this error code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::InvalidToken => StatusCode::UNAUTHORIZED,
            ErrorCode::InsufficientScope => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Returns the OAuth 2.0 error string for this error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidToken => "invalid_token",
            ErrorCode::InsufficientScope => "insufficient_scope",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ServiceUnavailable => "service_unavailable",
        }
    }
}

/// A domain-level error that can be converted into an HTTP response.
/// Follows OAuth 2.0 error response conventions with `error` and `error_description` fields.
#[derive(Debug, Clone)]
pub struct DomainError {
    /// The error code determining HTTP status and error type string.
    pub code: ErrorCode,
    /// A human-readable description of the error.
    pub description: String,
}

impl DomainError {
    /// Creates a new DomainError with the given code and description.
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    /// Creates an InvalidRequest error.
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, description)
    }

    /// Creates an InvalidToken error.
    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidToken, description)
    }

    /// Creates an InsufficientScope error.
    pub fn insufficient_scope(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InsufficientScope, description)
    }

    /// Creates a NotFound error.
    pub fn not_found(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, description)
    }

    /// Creates a Conflict error.
    pub fn conflict(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, description)
    }

    /// Creates a RateLimited error.
    pub fn rate_limited(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::RateLimited, description)
    }

    /// Creates a ServiceUnavailable error.
    pub fn service_unavailable(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::ServiceUnavailable, description)
    }
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.description)
    }
}

impl std::error::Error for DomainError {}

/// The JSON body structure for error responses, following OAuth 2.0 conventions.
#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: String,
}

impl IntoResponse for DomainError {
    fn into_response(self) -> Response {
        let status = self.code.status_code();
        let body = ErrorBody {
            error: self.code.as_str(),
            error_description: self.description,
        };
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_invalid_request_returns_400() {
        let err = DomainError::invalid_request("missing grant_type parameter");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_request");
        assert_eq!(json["error_description"], "missing grant_type parameter");
    }

    #[tokio::test]
    async fn test_invalid_token_returns_401() {
        let err = DomainError::invalid_token("token signature verification failed");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_token");
        assert_eq!(json["error_description"], "token signature verification failed");
    }

    #[tokio::test]
    async fn test_insufficient_scope_returns_403() {
        let err = DomainError::insufficient_scope("workload holds no billets");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "insufficient_scope");
        assert_eq!(json["error_description"], "workload holds no billets");
    }

    #[tokio::test]
    async fn test_not_found_returns_404() {
        let err = DomainError::not_found("billet not found");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "not_found");
        assert_eq!(json["error_description"], "billet not found");
    }

    #[tokio::test]
    async fn test_conflict_returns_409() {
        let err = DomainError::conflict("billet already exists");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "conflict");
        assert_eq!(json["error_description"], "billet already exists");
    }

    #[tokio::test]
    async fn test_rate_limited_returns_429() {
        let err = DomainError::rate_limited("rate limit exceeded");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "rate_limited");
        assert_eq!(json["error_description"], "rate limit exceeded");
    }

    #[tokio::test]
    async fn test_service_unavailable_returns_503() {
        let err = DomainError::service_unavailable("policy set not initialized");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "service_unavailable");
        assert_eq!(json["error_description"], "policy set not initialized");
    }

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(ErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(ErrorCode::InvalidToken.as_str(), "invalid_token");
        assert_eq!(ErrorCode::InsufficientScope.as_str(), "insufficient_scope");
        assert_eq!(ErrorCode::NotFound.as_str(), "not_found");
        assert_eq!(ErrorCode::Conflict.as_str(), "conflict");
        assert_eq!(ErrorCode::RateLimited.as_str(), "rate_limited");
        assert_eq!(ErrorCode::ServiceUnavailable.as_str(), "service_unavailable");
    }

    #[test]
    fn test_domain_error_display() {
        let err = DomainError::new(ErrorCode::InvalidRequest, "bad input");
        assert_eq!(format!("{}", err), "invalid_request: bad input");
    }

    #[tokio::test]
    async fn test_response_content_type_is_json() {
        let err = DomainError::invalid_request("test");
        let response = err.into_response();
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("application/json"));
    }
}
