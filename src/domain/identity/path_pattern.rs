use regex::Regex;
use std::collections::HashMap;

use crate::config::PathPatternConfig;

/// Compiled path patterns for extracting attributes from SPIFFE ID paths.
/// Immutable after construction (built once at startup).
#[derive(Debug, Clone)]
pub struct PathPatternMatcher {
    /// Compiled regex patterns in evaluation order.
    patterns: Vec<CompiledPattern>,
    /// The trust domain to strip from SPIFFE IDs before matching.
    trust_domain: String,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    regex: Regex,
    /// Names of the capture groups in this pattern (for fast attribute extraction).
    capture_names: Vec<String>,
}

/// Errors from path pattern compilation/validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPatternError {
    /// The regex pattern is invalid.
    InvalidRegex { pattern: String, reason: String },
    /// A capture group name is not a valid Cedar attribute name.
    InvalidCaptureName {
        pattern: String,
        name: String,
        reason: String,
    },
    /// Pattern has no named capture groups (warning-level, not fatal).
    NoCaptures { pattern: String },
}

impl std::fmt::Display for PathPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRegex { pattern, reason } => {
                write!(f, "invalid path pattern regex '{}': {}", pattern, reason)
            }
            Self::InvalidCaptureName {
                pattern,
                name,
                reason,
            } => {
                write!(
                    f,
                    "capture group '{}' in pattern '{}' is not a valid Cedar attribute name: {}",
                    name, pattern, reason
                )
            }
            Self::NoCaptures { pattern } => {
                write!(
                    f,
                    "path pattern '{}' has no named capture groups — it will match but extract no attributes",
                    pattern
                )
            }
        }
    }
}

impl std::error::Error for PathPatternError {}

/// Regex for validating capture group names as valid Cedar attribute names.
const CAPTURE_NAME_PATTERN: &str = r"^[a-zA-Z_][a-zA-Z0-9_]*$";

impl PathPatternMatcher {
    /// Compiles path patterns from configuration. Returns errors for invalid patterns.
    /// Patterns with zero named captures produce a warning but are still compiled.
    pub fn compile(
        trust_domain: &str,
        configs: &[PathPatternConfig],
    ) -> Result<Self, Vec<PathPatternError>> {
        let name_validator =
            Regex::new(CAPTURE_NAME_PATTERN).expect("capture name validator regex is valid");

        let mut patterns = Vec::with_capacity(configs.len());
        let mut errors = Vec::new();

        for config in configs {
            let regex = match Regex::new(&config.pattern) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(PathPatternError::InvalidRegex {
                        pattern: config.pattern.clone(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };

            // Extract named capture groups
            let capture_names: Vec<String> = regex
                .capture_names()
                .flatten()
                .map(|n| n.to_string())
                .collect();

            // Validate each capture group name
            for name in &capture_names {
                if !name_validator.is_match(name) {
                    errors.push(PathPatternError::InvalidCaptureName {
                        pattern: config.pattern.clone(),
                        name: name.clone(),
                        reason: "must match [a-zA-Z_][a-zA-Z0-9_]*".to_string(),
                    });
                }
            }

            patterns.push(CompiledPattern {
                regex,
                capture_names,
            });
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            patterns,
            trust_domain: trust_domain.to_string(),
        })
    }

    /// Extracts attributes from a SPIFFE ID by matching against compiled patterns.
    /// Returns the captured attributes from the first matching pattern,
    /// or an empty map if no pattern matches.
    pub fn extract(&self, spiffe_id: &str) -> HashMap<String, String> {
        let prefix = format!("spiffe://{}", self.trust_domain);

        let path = match spiffe_id.strip_prefix(&prefix) {
            Some(p) => p,
            None => return HashMap::new(),
        };

        for compiled in &self.patterns {
            if let Some(captures) = compiled.regex.captures(path) {
                let mut result = HashMap::new();
                for name in &compiled.capture_names {
                    if let Some(m) = captures.name(name) {
                        result.insert(name.clone(), m.as_str().to_string());
                    }
                }
                return result;
            }
        }

        HashMap::new()
    }

    /// Returns warnings for patterns that compiled but have no named captures.
    pub fn warnings(&self) -> Vec<PathPatternError> {
        self.patterns
            .iter()
            .filter(|p| p.capture_names.is_empty())
            .map(|p| PathPatternError::NoCaptures {
                pattern: p.regex.as_str().to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_valid_patterns() {
        let configs = vec![
            PathPatternConfig {
                pattern: r"^/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)$".to_string(),
            },
            PathPatternConfig {
                pattern: r"^/env/(?P<environment>[^/]+)/ns/(?P<namespace>[^/]+)$".to_string(),
            },
        ];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        assert_eq!(matcher.patterns.len(), 2);
        assert!(matcher.warnings().is_empty());
    }

    #[test]
    fn test_compile_invalid_regex_returns_error() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/ns/(?P<namespace>[^/]+".to_string(), // unclosed group
        }];

        let err = PathPatternMatcher::compile("example.com", &configs).unwrap_err();
        assert_eq!(err.len(), 1);
        match &err[0] {
            PathPatternError::InvalidRegex { pattern, .. } => {
                assert_eq!(pattern, r"^/ns/(?P<namespace>[^/]+");
            }
            other => panic!("expected InvalidRegex, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_invalid_capture_name_with_hyphen() {
        // The regex crate itself rejects hyphens in capture group names,
        // so this surfaces as an InvalidRegex error.
        let configs = vec![PathPatternConfig {
            pattern: r"^/(?P<pod-name>[^/]+)$".to_string(),
        }];

        let err = PathPatternMatcher::compile("example.com", &configs).unwrap_err();
        assert_eq!(err.len(), 1);
        match &err[0] {
            PathPatternError::InvalidRegex { pattern, .. } => {
                assert_eq!(pattern, r"^/(?P<pod-name>[^/]+)$");
            }
            other => panic!("expected InvalidRegex, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_invalid_capture_name_digit_prefix() {
        // The regex crate itself rejects digit-prefixed capture group names,
        // so this surfaces as an InvalidRegex error.
        let configs = vec![PathPatternConfig {
            pattern: r"^/(?P<123start>[^/]+)$".to_string(),
        }];

        let err = PathPatternMatcher::compile("example.com", &configs).unwrap_err();
        assert_eq!(err.len(), 1);
        match &err[0] {
            PathPatternError::InvalidRegex { pattern, .. } => {
                assert_eq!(pattern, r"^/(?P<123start>[^/]+)$");
            }
            other => panic!("expected InvalidRegex, got {:?}", other),
        }
    }

    #[test]
    fn test_compile_no_captures_produces_warning() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/static/path$".to_string(),
        }];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        let warnings = matcher.warnings();
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            PathPatternError::NoCaptures { pattern } => {
                assert_eq!(pattern, r"^/static/path$");
            }
            other => panic!("expected NoCaptures, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_first_pattern_matches() {
        let configs = vec![
            PathPatternConfig {
                pattern: r"^/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)$".to_string(),
            },
            PathPatternConfig {
                pattern: r"^/env/(?P<environment>[^/]+)$".to_string(),
            },
        ];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        let result = matcher.extract("spiffe://example.com/ns/billing/sa/api");

        assert_eq!(result.len(), 2);
        assert_eq!(result["namespace"], "billing");
        assert_eq!(result["service_account"], "api");
    }

    #[test]
    fn test_extract_second_pattern_matches_when_first_does_not() {
        let configs = vec![
            PathPatternConfig {
                pattern: r"^/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)$".to_string(),
            },
            PathPatternConfig {
                pattern: r"^/env/(?P<environment>[^/]+)$".to_string(),
            },
        ];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        let result = matcher.extract("spiffe://example.com/env/production");

        assert_eq!(result.len(), 1);
        assert_eq!(result["environment"], "production");
    }

    #[test]
    fn test_extract_no_pattern_matches_returns_empty() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/ns/(?P<namespace>[^/]+)/sa/(?P<service_account>[^/]+)$".to_string(),
        }];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        let result = matcher.extract("spiffe://example.com/unknown/path/here");

        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_different_trust_domain_returns_empty() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/ns/(?P<namespace>[^/]+)$".to_string(),
        }];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        let result = matcher.extract("spiffe://other-domain.com/ns/billing");

        assert!(result.is_empty());
    }

    #[test]
    fn test_compile_collects_multiple_errors() {
        let configs = vec![
            PathPatternConfig {
                pattern: r"^/(?P<pod-name>[^/]+)$".to_string(), // invalid regex (hyphen in name)
            },
            PathPatternConfig {
                pattern: r"^/unclosed[".to_string(), // invalid regex (unclosed bracket)
            },
        ];

        let err = PathPatternMatcher::compile("example.com", &configs).unwrap_err();
        assert_eq!(err.len(), 2);
        // Both produce InvalidRegex since the regex crate rejects them at parse time
        assert!(matches!(&err[0], PathPatternError::InvalidRegex { .. }));
        assert!(matches!(&err[1], PathPatternError::InvalidRegex { .. }));
    }

    #[test]
    fn test_extract_with_optional_group_not_captured() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/ns/(?P<namespace>[^/]+)(/sa/(?P<service_account>[^/]+))?$".to_string(),
        }];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        // Path matches but the optional service_account group doesn't capture
        let result = matcher.extract("spiffe://example.com/ns/billing");

        assert_eq!(result.len(), 1);
        assert_eq!(result["namespace"], "billing");
        assert!(!result.contains_key("service_account"));
    }

    #[test]
    fn test_compile_valid_underscore_prefix_name() {
        let configs = vec![PathPatternConfig {
            pattern: r"^/(?P<_private>[^/]+)$".to_string(),
        }];

        let matcher = PathPatternMatcher::compile("example.com", &configs).unwrap();
        assert!(matcher.warnings().is_empty());
    }
}
