//! Tag validation for billet metadata.
//!
//! Tags must conform to `key:value` format where both key and value are non-empty
//! and contain only alphanumeric characters, hyphens, underscores, and dots.
//! The first character of both key and value must be alphanumeric.

/// Returns true if the character is a valid tag character (alphanumeric, hyphen, underscore, dot).
fn is_valid_tag_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// Returns true if the character is valid as the first character of a key or value (alphanumeric only).
fn is_valid_first_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Validates that a tag conforms to `key:value` format where both key and value
/// are non-empty and contain only [a-zA-Z0-9\-_.] characters.
/// The first character of both key and value must be alphanumeric.
pub fn validate_tag(tag: &str) -> Result<(), String> {
    // Find the first colon — this separates key from value
    let colon_pos = match tag.find(':') {
        Some(pos) => pos,
        None => {
            return Err(format!(
                "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
                tag
            ));
        }
    };

    let key = &tag[..colon_pos];
    let value = &tag[colon_pos + 1..];

    // Both key and value must be non-empty
    if key.is_empty() || value.is_empty() {
        return Err(format!(
            "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
            tag
        ));
    }

    // First character of key must be alphanumeric
    if !is_valid_first_char(key.chars().next().unwrap()) {
        return Err(format!(
            "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
            tag
        ));
    }

    // All characters of key must be valid
    if !key.chars().all(is_valid_tag_char) {
        return Err(format!(
            "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
            tag
        ));
    }

    // First character of value must be alphanumeric
    if !is_valid_first_char(value.chars().next().unwrap()) {
        return Err(format!(
            "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
            tag
        ));
    }

    // All characters of value must be valid
    if !value.chars().all(is_valid_tag_char) {
        return Err(format!(
            "invalid tag '{}': must be key:value format with alphanumeric, hyphen, underscore, or dot characters",
            tag
        ));
    }

    Ok(())
}

/// Validates a slice of tags, returning the first invalid tag as an error.
pub fn validate_tags(tags: &[String]) -> Result<(), String> {
    for tag in tags {
        validate_tag(tag)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tags() {
        assert!(validate_tag("env:production").is_ok());
        assert!(validate_tag("team:billing-ops").is_ok());
        assert!(validate_tag("sensitivity:high").is_ok());
        assert!(validate_tag("a:b").is_ok());
        assert!(validate_tag("system:true").is_ok());
        assert!(validate_tag("k8s.io:namespace").is_ok());
        assert!(validate_tag("my_key:my_value").is_ok());
        assert!(validate_tag("version:1.0.0").is_ok());
        assert!(validate_tag("A1-test:B2-value").is_ok());
    }

    #[test]
    fn test_invalid_tag_no_colon() {
        assert!(validate_tag("novalue").is_err());
    }

    #[test]
    fn test_invalid_tag_empty_string() {
        assert!(validate_tag("").is_err());
    }

    #[test]
    fn test_invalid_tag_empty_key() {
        assert!(validate_tag(":value").is_err());
    }

    #[test]
    fn test_invalid_tag_empty_value() {
        assert!(validate_tag("key:").is_err());
    }

    #[test]
    fn test_invalid_tag_bad_characters() {
        assert!(validate_tag("env:prod!").is_err());
        assert!(validate_tag("env:prod ").is_err());
        assert!(validate_tag("env :prod").is_err());
        assert!(validate_tag("k@y:value").is_err());
        assert!(validate_tag("key:val=ue").is_err());
    }

    #[test]
    fn test_invalid_tag_first_char_not_alphanumeric() {
        assert!(validate_tag("-key:value").is_err());
        assert!(validate_tag(".key:value").is_err());
        assert!(validate_tag("_key:value").is_err());
        assert!(validate_tag("key:-value").is_err());
        assert!(validate_tag("key:.value").is_err());
        assert!(validate_tag("key:_value").is_err());
    }

    #[test]
    fn test_multiple_colons_valid() {
        // The first colon is the separator; subsequent colons are invalid chars in value
        // "key:val:ue" -> key="key", value="val:ue" -> colon is not a valid tag char
        assert!(validate_tag("key:val:ue").is_err());
    }

    #[test]
    fn test_validate_tags_all_valid() {
        let tags = vec![
            "env:production".to_string(),
            "team:billing".to_string(),
            "sensitivity:high".to_string(),
        ];
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn test_validate_tags_empty_slice() {
        let tags: Vec<String> = vec![];
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn test_validate_tags_first_invalid() {
        let tags = vec![
            "env:production".to_string(),
            "bad tag!".to_string(),
            "team:billing".to_string(),
        ];
        let result = validate_tags(&tags);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad tag!"));
    }
}
