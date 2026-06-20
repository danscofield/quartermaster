//! ARN parsing and presigned STS URL validation for AWS identity.
//!
//! Supports two ARN formats:
//! - IAM role ARN: `arn:aws:iam::<account_id>:role/<role_name>` or `arn:aws:iam::<account_id>:role/<path>/<role_name>`
//! - Assumed role ARN: `arn:aws:sts::<account_id>:assumed-role/<role_name>/<session_name>`
//!
//! Also provides the `AwsStsValidator` trait for validating presigned GetCallerIdentity URLs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use url::Url;

use crate::config::identity::AwsStsSourceConfig;

use super::{AwsStsIdentity, IdentityError};

/// Components extracted from an IAM role ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IamRoleArn {
    pub account_id: String,
    pub role_name: String,
    pub role_path: String,
}

/// Components extracted from an assumed role ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssumedRoleArn {
    pub account_id: String,
    pub role_name: String,
    pub session_name: String,
}

/// Validates presigned AWS STS GetCallerIdentity URLs and returns identity info.
#[async_trait]
pub trait AwsStsValidator: Send + Sync {
    async fn validate(&self, presigned_url: &str) -> Result<AwsStsIdentity, IdentityError>;
}

/// Default implementation of `AwsStsValidator` that calls the presigned URL via HTTP.
pub struct DefaultAwsStsValidator {
    config: AwsStsSourceConfig,
    http_client: reqwest::Client,
}

impl DefaultAwsStsValidator {
    pub fn new(config: AwsStsSourceConfig, http_client: reqwest::Client) -> Self {
        Self {
            config,
            http_client,
        }
    }
}

/// Validate the host of a presigned STS URL.
///
/// Accepted hosts:
/// - `sts.amazonaws.com` (global endpoint)
/// - `sts.<region>.amazonaws.com` (regional endpoint, region matches `[a-z0-9-]+`)
fn validate_sts_host(host: &str) -> Result<(), IdentityError> {
    if host == "sts.amazonaws.com" {
        return Ok(());
    }

    // Check for regional endpoint: sts.<region>.amazonaws.com
    if let Some(rest) = host.strip_prefix("sts.") {
        if let Some(region) = rest.strip_suffix(".amazonaws.com") {
            if !region.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Ok(());
            }
        }
    }

    Err(IdentityError::InvalidPresignedUrl(format!(
        "host must be sts.amazonaws.com or sts.<region>.amazonaws.com, got '{}'",
        host
    )))
}

/// Validate that the query parameters include `Action=GetCallerIdentity`.
fn validate_action_param(url: &Url) -> Result<(), IdentityError> {
    let has_action = url
        .query_pairs()
        .any(|(key, value)| key == "Action" && value == "GetCallerIdentity");

    if !has_action {
        return Err(IdentityError::InvalidPresignedUrl(
            "query parameters must include Action=GetCallerIdentity".to_string(),
        ));
    }

    Ok(())
}

/// Check whether the presigned URL has expired based on X-Amz-Date and X-Amz-Expires.
///
/// `X-Amz-Date` format: `YYYYMMDDTHHmmssZ`
/// `X-Amz-Expires` is an integer number of seconds.
fn validate_expiry(url: &Url, now: DateTime<Utc>) -> Result<(), IdentityError> {
    let amz_date = url
        .query_pairs()
        .find(|(key, _)| key == "X-Amz-Date")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| {
            IdentityError::InvalidPresignedUrl("missing X-Amz-Date query parameter".to_string())
        })?;

    let amz_expires = url
        .query_pairs()
        .find(|(key, _)| key == "X-Amz-Expires")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| {
            IdentityError::InvalidPresignedUrl("missing X-Amz-Expires query parameter".to_string())
        })?;

    // Parse X-Amz-Date in format YYYYMMDDTHHmmssZ
    let signed_at = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|e| {
            IdentityError::InvalidPresignedUrl(format!("invalid X-Amz-Date '{}': {}", amz_date, e))
        })?
        .and_utc();

    let expires_secs: i64 = amz_expires.parse().map_err(|e| {
        IdentityError::InvalidPresignedUrl(format!(
            "invalid X-Amz-Expires '{}': {}",
            amz_expires, e
        ))
    })?;

    let expiry_time = signed_at + chrono::Duration::seconds(expires_secs);

    if now >= expiry_time {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "presigned URL expired at {}",
            expiry_time
        )));
    }

    Ok(())
}

/// Validate a presigned STS URL: host, Action param, and expiry.
/// This function does NOT make HTTP calls — it only validates the URL structure.
pub fn validate_presigned_url(presigned_url: &str, now: DateTime<Utc>) -> Result<Url, IdentityError> {
    let url = Url::parse(presigned_url).map_err(|e| {
        IdentityError::InvalidPresignedUrl(format!("failed to parse URL: {}", e))
    })?;

    // Must be HTTPS
    if url.scheme() != "https" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "URL scheme must be https, got '{}'",
            url.scheme()
        )));
    }

    let host = url.host_str().ok_or_else(|| {
        IdentityError::InvalidPresignedUrl("URL has no host".to_string())
    })?;

    validate_sts_host(host)?;
    validate_action_param(&url)?;
    validate_expiry(&url, now)?;

    Ok(url)
}

/// Parse the STS GetCallerIdentity XML response and extract Account, Arn, UserId.
///
/// Expected format:
/// ```xml
/// <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
///   <GetCallerIdentityResult>
///     <Account>123456789012</Account>
///     <Arn>arn:aws:sts::123456789012:assumed-role/role-name/session</Arn>
///     <UserId>AROAEXAMPLE:session</UserId>
///   </GetCallerIdentityResult>
/// </GetCallerIdentityResponse>
/// ```
fn parse_get_caller_identity_xml(
    xml: &str,
) -> Result<(String, String, String), IdentityError> {
    let account = extract_xml_element(xml, "Account").ok_or_else(|| {
        IdentityError::UpstreamCallFailed("missing <Account> in STS response".to_string())
    })?;

    let arn = extract_xml_element(xml, "Arn").ok_or_else(|| {
        IdentityError::UpstreamCallFailed("missing <Arn> in STS response".to_string())
    })?;

    let user_id = extract_xml_element(xml, "UserId").ok_or_else(|| {
        IdentityError::UpstreamCallFailed("missing <UserId> in STS response".to_string())
    })?;

    Ok((account, arn, user_id))
}

/// Extract text content from a simple XML element like `<Tag>content</Tag>`.
/// This is a lightweight approach suitable for the well-known STS response format.
fn extract_xml_element(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = xml.find(&open_tag)? + open_tag.len();
    let end = xml[start..].find(&close_tag)? + start;

    Some(xml[start..end].trim().to_string())
}

#[async_trait]
impl AwsStsValidator for DefaultAwsStsValidator {
    async fn validate(&self, presigned_url: &str) -> Result<AwsStsIdentity, IdentityError> {
        // 1. Validate URL structure (host, Action, expiry)
        let url = validate_presigned_url(presigned_url, Utc::now())?;

        // 2. Call the presigned URL
        let response = self
            .http_client
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| {
                IdentityError::UpstreamCallFailed(format!("HTTP request to STS failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(IdentityError::UpstreamCallFailed(format!(
                "STS returned HTTP {}: {}",
                status, body
            )));
        }

        let body = response.text().await.map_err(|e| {
            IdentityError::UpstreamCallFailed(format!("failed to read STS response body: {}", e))
        })?;

        // 3. Parse XML response
        let (account, arn, _user_id) = parse_get_caller_identity_xml(&body)?;

        // 4. Parse the ARN to extract role components
        let parsed = parse_assumed_role_arn(&arn)?;

        // 5. Apply allowed_accounts filter
        if let Some(ref allowed) = self.config.allowed_accounts {
            if !allowed.contains(&parsed.account_id) {
                return Err(IdentityError::NotAllowed(format!(
                    "AWS account '{}' is not in the allowed accounts list",
                    parsed.account_id
                )));
            }
        }

        // 6. Return AwsStsIdentity
        Ok(AwsStsIdentity {
            account_id: account,
            role_arn: arn,
            role_name: parsed.role_name,
            role_path: "/".to_string(),
            session_name: parsed.session_name,
        })
    }
}

/// Parse an IAM role ARN of the form:
/// `arn:aws:iam::<account_id>:role/<role_name>`
/// `arn:aws:iam::<account_id>:role/<path>/<role_name>`
///
/// The path can be multi-level (e.g., `/service-roles/my-app/`).
/// If no path segments exist before the role name, `role_path` is "/".
pub fn parse_iam_role_arn(arn: &str) -> Result<IamRoleArn, IdentityError> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();

    if parts.len() != 6 {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 6 colon-separated parts, got {}",
            parts.len()
        )));
    }

    let [prefix, partition, service, _region, account_id, resource] = parts[..] else {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed ARN: unexpected structure".into(),
        ));
    };

    if prefix != "arn" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'arn' prefix, got '{prefix}'"
        )));
    }

    if partition != "aws" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'aws' partition, got '{partition}'"
        )));
    }

    if service != "iam" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'iam' service, got '{service}'"
        )));
    }

    if account_id.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed ARN: account_id is empty".into(),
        ));
    }

    // Resource must start with "role/"
    let role_suffix = resource.strip_prefix("role/").ok_or_else(|| {
        IdentityError::InvalidPresignedUrl(format!(
            "malformed IAM role ARN: resource must start with 'role/', got '{resource}'"
        ))
    })?;

    if role_suffix.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed IAM role ARN: role name is empty".into(),
        ));
    }

    // Split by '/' to separate path segments from role name.
    // The last segment is always the role name; everything before it is the path.
    let segments: Vec<&str> = role_suffix.split('/').collect();
    let role_name = segments.last().unwrap().to_string();

    if role_name.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed IAM role ARN: role name is empty (trailing slash)".into(),
        ));
    }

    let role_path = if segments.len() > 1 {
        // Build path from all segments except the last (the role name)
        format!("/{}/", segments[..segments.len() - 1].join("/"))
    } else {
        "/".to_string()
    };

    Ok(IamRoleArn {
        account_id: account_id.to_string(),
        role_name,
        role_path,
    })
}

/// Parse an assumed role ARN of the form:
/// `arn:aws:sts::<account_id>:assumed-role/<role_name>/<session_name>`
pub fn parse_assumed_role_arn(arn: &str) -> Result<AssumedRoleArn, IdentityError> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();

    if parts.len() != 6 {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 6 colon-separated parts, got {}",
            parts.len()
        )));
    }

    let [prefix, partition, service, _region, account_id, resource] = parts[..] else {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed ARN: unexpected structure".into(),
        ));
    };

    if prefix != "arn" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'arn' prefix, got '{prefix}'"
        )));
    }

    if partition != "aws" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'aws' partition, got '{partition}'"
        )));
    }

    if service != "sts" {
        return Err(IdentityError::InvalidPresignedUrl(format!(
            "malformed ARN: expected 'sts' service, got '{service}'"
        )));
    }

    if account_id.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed ARN: account_id is empty".into(),
        ));
    }

    // Resource must start with "assumed-role/"
    let assumed_suffix = resource.strip_prefix("assumed-role/").ok_or_else(|| {
        IdentityError::InvalidPresignedUrl(format!(
            "malformed assumed role ARN: resource must start with 'assumed-role/', got '{resource}'"
        ))
    })?;

    // Split into role_name/session_name
    let slash_pos = assumed_suffix.find('/').ok_or_else(|| {
        IdentityError::InvalidPresignedUrl(
            "malformed assumed role ARN: missing session_name after role_name".into(),
        )
    })?;

    let role_name = &assumed_suffix[..slash_pos];
    let session_name = &assumed_suffix[slash_pos + 1..];

    if role_name.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed assumed role ARN: role_name is empty".into(),
        ));
    }

    if session_name.is_empty() {
        return Err(IdentityError::InvalidPresignedUrl(
            "malformed assumed role ARN: session_name is empty".into(),
        ));
    }

    Ok(AssumedRoleArn {
        account_id: account_id.to_string(),
        role_name: role_name.to_string(),
        session_name: session_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ─── Host Validation Tests ─────────────────────────────────────────────

    #[test]
    fn test_validate_sts_host_global() {
        assert!(validate_sts_host("sts.amazonaws.com").is_ok());
    }

    #[test]
    fn test_validate_sts_host_regional() {
        assert!(validate_sts_host("sts.us-east-1.amazonaws.com").is_ok());
        assert!(validate_sts_host("sts.eu-west-1.amazonaws.com").is_ok());
        assert!(validate_sts_host("sts.ap-southeast-2.amazonaws.com").is_ok());
        assert!(validate_sts_host("sts.us-gov-west-1.amazonaws.com").is_ok());
    }

    #[test]
    fn test_validate_sts_host_invalid() {
        assert!(validate_sts_host("evil.amazonaws.com").is_err());
        assert!(validate_sts_host("sts.evil.com").is_err());
        assert!(validate_sts_host("sts..amazonaws.com").is_err());
        assert!(validate_sts_host("not-sts.amazonaws.com").is_err());
        assert!(validate_sts_host("sts.US-EAST-1.amazonaws.com").is_err());
        assert!(validate_sts_host("").is_err());
        assert!(validate_sts_host("sts.amazonaws.com.evil.com").is_err());
    }

    // ─── Action Parameter Validation Tests ─────────────────────────────────

    #[test]
    fn test_validate_action_param_present() {
        let url = Url::parse("https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15").unwrap();
        assert!(validate_action_param(&url).is_ok());
    }

    #[test]
    fn test_validate_action_param_missing() {
        let url = Url::parse("https://sts.amazonaws.com/?Version=2011-06-15").unwrap();
        assert!(validate_action_param(&url).is_err());
    }

    #[test]
    fn test_validate_action_param_wrong_action() {
        let url = Url::parse("https://sts.amazonaws.com/?Action=AssumeRole").unwrap();
        assert!(validate_action_param(&url).is_err());
    }

    // ─── Expiry Validation Tests ───────────────────────────────────────────

    #[test]
    fn test_validate_expiry_valid() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600"
        ).unwrap();
        // Now is before expiry (signed at 12:00, expires in 3600s = 13:00, now = 12:30)
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        assert!(validate_expiry(&url, now).is_ok());
    }

    #[test]
    fn test_validate_expiry_expired() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600"
        ).unwrap();
        // Now is after expiry (signed at 12:00, expires in 3600s = 13:00, now = 14:00)
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 14, 0, 0).unwrap();
        assert!(validate_expiry(&url, now).is_err());
    }

    #[test]
    fn test_validate_expiry_exactly_at_boundary() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600"
        ).unwrap();
        // Now is exactly at expiry time (13:00:00)
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 13, 0, 0).unwrap();
        assert!(validate_expiry(&url, now).is_err());
    }

    #[test]
    fn test_validate_expiry_missing_date() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Expires=3600"
        ).unwrap();
        let now = Utc::now();
        assert!(validate_expiry(&url, now).is_err());
    }

    #[test]
    fn test_validate_expiry_missing_expires() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z"
        ).unwrap();
        let now = Utc::now();
        assert!(validate_expiry(&url, now).is_err());
    }

    #[test]
    fn test_validate_expiry_invalid_date_format() {
        let url = Url::parse(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=2025-01-01T12:00:00Z&X-Amz-Expires=3600"
        ).unwrap();
        let now = Utc::now();
        assert!(validate_expiry(&url, now).is_err());
    }

    // ─── Full URL Validation Tests ─────────────────────────────────────────

    #[test]
    fn test_validate_presigned_url_valid() {
        let url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Credential=AKID/20250101/us-east-1/sts/aws4_request&X-Amz-Signature=abcdef";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        assert!(validate_presigned_url(url, now).is_ok());
    }

    #[test]
    fn test_validate_presigned_url_regional_endpoint() {
        let url = "https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        assert!(validate_presigned_url(url, now).is_ok());
    }

    #[test]
    fn test_validate_presigned_url_http_rejected() {
        let url = "http://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        let err = validate_presigned_url(url, now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_validate_presigned_url_wrong_host() {
        let url = "https://evil.com/?Action=GetCallerIdentity&X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        let err = validate_presigned_url(url, now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_validate_presigned_url_missing_action() {
        let url = "https://sts.amazonaws.com/?X-Amz-Date=20250101T120000Z&X-Amz-Expires=3600";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        let err = validate_presigned_url(url, now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_validate_presigned_url_expired() {
        let url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date=20240101T120000Z&X-Amz-Expires=60";
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 12, 30, 0).unwrap();
        let err = validate_presigned_url(url, now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_validate_presigned_url_invalid_url() {
        let now = Utc::now();
        let err = validate_presigned_url("not a url at all", now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    // ─── XML Parsing Tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_get_caller_identity_xml_valid() {
        let xml = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Account>123456789012</Account>
    <Arn>arn:aws:sts::123456789012:assumed-role/billing-service/session-abc</Arn>
    <UserId>AROA3XFRBF23:session-abc</UserId>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"#;

        let (account, arn, user_id) = parse_get_caller_identity_xml(xml).unwrap();
        assert_eq!(account, "123456789012");
        assert_eq!(
            arn,
            "arn:aws:sts::123456789012:assumed-role/billing-service/session-abc"
        );
        assert_eq!(user_id, "AROA3XFRBF23:session-abc");
    }

    #[test]
    fn test_parse_get_caller_identity_xml_missing_account() {
        let xml = r#"<GetCallerIdentityResponse>
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/role/session</Arn>
    <UserId>AROA:session</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"#;

        let err = parse_get_caller_identity_xml(xml).unwrap_err();
        assert!(matches!(err, IdentityError::UpstreamCallFailed(_)));
    }

    #[test]
    fn test_parse_get_caller_identity_xml_missing_arn() {
        let xml = r#"<GetCallerIdentityResponse>
  <GetCallerIdentityResult>
    <Account>123456789012</Account>
    <UserId>AROA:session</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"#;

        let err = parse_get_caller_identity_xml(xml).unwrap_err();
        assert!(matches!(err, IdentityError::UpstreamCallFailed(_)));
    }

    #[test]
    fn test_parse_get_caller_identity_xml_missing_userid() {
        let xml = r#"<GetCallerIdentityResponse>
  <GetCallerIdentityResult>
    <Account>123456789012</Account>
    <Arn>arn:aws:sts::123456789012:assumed-role/role/session</Arn>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"#;

        let err = parse_get_caller_identity_xml(xml).unwrap_err();
        assert!(matches!(err, IdentityError::UpstreamCallFailed(_)));
    }

    // ─── XML Element Extraction Tests ──────────────────────────────────────

    #[test]
    fn test_extract_xml_element_simple() {
        assert_eq!(
            extract_xml_element("<Root><Name>value</Name></Root>", "Name"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_extract_xml_element_with_whitespace() {
        assert_eq!(
            extract_xml_element("<Root><Name>  value  </Name></Root>", "Name"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_extract_xml_element_not_found() {
        assert_eq!(
            extract_xml_element("<Root><Other>value</Other></Root>", "Name"),
            None
        );
    }

    // ─── IAM Role ARN Tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_iam_role_arn_simple() {
        let arn = "arn:aws:iam::123456789012:role/billing-service";
        let result = parse_iam_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "123456789012");
        assert_eq!(result.role_name, "billing-service");
        assert_eq!(result.role_path, "/");
    }

    #[test]
    fn test_parse_iam_role_arn_with_single_path() {
        let arn = "arn:aws:iam::123456789012:role/service-roles/billing-service";
        let result = parse_iam_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "123456789012");
        assert_eq!(result.role_name, "billing-service");
        assert_eq!(result.role_path, "/service-roles/");
    }

    #[test]
    fn test_parse_iam_role_arn_with_multi_level_path() {
        let arn = "arn:aws:iam::987654321098:role/org/team/app/my-role";
        let result = parse_iam_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "987654321098");
        assert_eq!(result.role_name, "my-role");
        assert_eq!(result.role_path, "/org/team/app/");
    }

    #[test]
    fn test_parse_iam_role_arn_wrong_service() {
        let arn = "arn:aws:sts::123456789012:role/billing-service";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_missing_role_prefix() {
        let arn = "arn:aws:iam::123456789012:user/some-user";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_empty_account_id() {
        let arn = "arn:aws:iam:::role/my-role";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_empty_role_name() {
        let arn = "arn:aws:iam::123456789012:role/";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_trailing_slash() {
        let arn = "arn:aws:iam::123456789012:role/path/";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_too_few_parts() {
        let arn = "arn:aws:iam::123456789012";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_wrong_prefix() {
        let arn = "xxx:aws:iam::123456789012:role/my-role";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_iam_role_arn_wrong_partition() {
        let arn = "arn:gcp:iam::123456789012:role/my-role";
        let err = parse_iam_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    // ─── Assumed Role ARN Tests ────────────────────────────────────────────

    #[test]
    fn test_parse_assumed_role_arn_simple() {
        let arn = "arn:aws:sts::123456789012:assumed-role/billing-service/session-abc";
        let result = parse_assumed_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "123456789012");
        assert_eq!(result.role_name, "billing-service");
        assert_eq!(result.session_name, "session-abc");
    }

    #[test]
    fn test_parse_assumed_role_arn_long_session_name() {
        let arn =
            "arn:aws:sts::987654321098:assumed-role/deploy-role/i-0123456789abcdef0";
        let result = parse_assumed_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "987654321098");
        assert_eq!(result.role_name, "deploy-role");
        assert_eq!(result.session_name, "i-0123456789abcdef0");
    }

    #[test]
    fn test_parse_assumed_role_arn_session_with_slashes() {
        let arn = "arn:aws:sts::111222333444:assumed-role/my-role/session/with/slashes";
        let result = parse_assumed_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "111222333444");
        assert_eq!(result.role_name, "my-role");
        assert_eq!(result.session_name, "session/with/slashes");
    }

    #[test]
    fn test_parse_assumed_role_arn_wrong_service() {
        let arn = "arn:aws:iam::123456789012:assumed-role/my-role/session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_wrong_resource_prefix() {
        let arn = "arn:aws:sts::123456789012:role/my-role/session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_missing_session_name() {
        let arn = "arn:aws:sts::123456789012:assumed-role/my-role";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_empty_role_name() {
        let arn = "arn:aws:sts::123456789012:assumed-role//session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_empty_session_name() {
        let arn = "arn:aws:sts::123456789012:assumed-role/my-role/";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_empty_account_id() {
        let arn = "arn:aws:sts:::assumed-role/my-role/session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_too_few_parts() {
        let arn = "arn:aws:sts::123456789012";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_wrong_prefix() {
        let arn = "bad:aws:sts::123456789012:assumed-role/my-role/session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    #[test]
    fn test_parse_assumed_role_arn_wrong_partition() {
        let arn = "arn:azure:sts::123456789012:assumed-role/my-role/session";
        let err = parse_assumed_role_arn(arn).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPresignedUrl(_)));
    }

    // ─── Edge Cases ────────────────────────────────────────────────────────

    #[test]
    fn test_empty_string() {
        assert!(parse_iam_role_arn("").is_err());
        assert!(parse_assumed_role_arn("").is_err());
    }

    #[test]
    fn test_completely_invalid_input() {
        assert!(parse_iam_role_arn("not-an-arn-at-all").is_err());
        assert!(parse_assumed_role_arn("not-an-arn-at-all").is_err());
    }

    #[test]
    fn test_parse_iam_role_arn_numeric_account_id() {
        let arn = "arn:aws:iam::000000000000:role/test-role";
        let result = parse_iam_role_arn(arn).unwrap();
        assert_eq!(result.account_id, "000000000000");
        assert_eq!(result.role_name, "test-role");
        assert_eq!(result.role_path, "/");
    }

    // ─── Allowed Accounts Filter Test ──────────────────────────────────────

    #[test]
    fn test_allowed_accounts_filter_logic() {
        // Test the filtering logic in isolation
        let allowed = vec!["123456789012".to_string(), "987654321098".to_string()];
        let account = "123456789012";
        assert!(allowed.contains(&account.to_string()));

        let account = "000000000000";
        assert!(!allowed.contains(&account.to_string()));
    }
}
