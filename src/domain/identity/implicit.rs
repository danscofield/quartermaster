use std::collections::{HashMap, HashSet};

use crate::config::identity::OidcSourceConfig;

/// A single claim-to-billet mapping configuration.
#[derive(Debug, Clone)]
pub struct ImplicitClaimMapping {
    pub claim_name: String,
    pub billet_prefix: String,
    pub in_tokens: bool,
}

/// Result of implicit mapping, separating token-visible vs admin-only billets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImplicitBilletResult {
    /// Billets that should appear in issued JWTs/certs (in_tokens = true)
    pub token_billets: Vec<String>,
    /// All implicit billets including admin-only (for Cedar admin evaluation)
    pub all_billets: Vec<String>,
}

/// Derives implicit billets from IdP token claims based on configured claim mappings.
///
/// For each configured OIDC source with `implicit_claims` entries, this mapper produces
/// billets of the form `<billet_prefix>:<claim_value>` for every value in the mapped claim.
/// Multiple claim mappings on the same IdP produce independent sets that are unioned.
pub struct ImplicitBilletMapper {
    /// Map from IdP prefix → list of claim mappings
    mappings: HashMap<String, Vec<ImplicitClaimMapping>>,
    /// Set of all reserved billet prefixes (from all implicit_claims configs)
    reserved_prefixes: HashSet<String>,
}

impl ImplicitBilletMapper {
    /// Build the mapper from OIDC source configurations.
    ///
    /// Extracts all `implicit_claims` entries from each source, keyed by IdP prefix,
    /// and collects all `billet_prefix` values into the reserved prefix set.
    pub fn from_config(oidc_sources: &[OidcSourceConfig]) -> Self {
        let mut mappings: HashMap<String, Vec<ImplicitClaimMapping>> = HashMap::new();
        let mut reserved_prefixes: HashSet<String> = HashSet::new();

        for source in oidc_sources {
            let mut source_mappings = Vec::new();
            for claim_config in &source.implicit_claims {
                reserved_prefixes.insert(claim_config.billet_prefix.clone());
                source_mappings.push(ImplicitClaimMapping {
                    claim_name: claim_config.claim.clone(),
                    billet_prefix: claim_config.billet_prefix.clone(),
                    in_tokens: claim_config.in_tokens,
                });
            }
            if !source_mappings.is_empty() {
                mappings.insert(source.prefix.clone(), source_mappings);
            }
        }

        Self {
            mappings,
            reserved_prefixes,
        }
    }

    /// Derive implicit billets for an identity from the given IdP.
    ///
    /// For each mapping associated with the IdP:
    /// - Look up the claim name in the claims map
    /// - For each value in the claim, produce a billet: `<billet_prefix>:<claim_value>`
    /// - If `in_tokens = true`, add to both `token_billets` and `all_billets`
    /// - If `in_tokens = false`, add to `all_billets` only
    pub fn derive_billets(
        &self,
        idp_prefix: &str,
        claims: &HashMap<String, Vec<String>>,
    ) -> ImplicitBilletResult {
        let mut result = ImplicitBilletResult::default();

        let Some(claim_mappings) = self.mappings.get(idp_prefix) else {
            return result;
        };

        for mapping in claim_mappings {
            if let Some(values) = claims.get(&mapping.claim_name) {
                for value in values {
                    let billet = format!("{}:{}", mapping.billet_prefix, value);
                    result.all_billets.push(billet.clone());
                    if mapping.in_tokens {
                        result.token_billets.push(billet);
                    }
                }
            }
        }

        result
    }

    /// Returns the set of reserved billet prefixes.
    ///
    /// These prefixes are derived from all `billet_prefix` values across all configured
    /// implicit claim mappings. Cedar-evaluated billets starting with any of these prefixes
    /// should be stripped, and the admin API should reject billet creation with these prefixes.
    pub fn reserved_prefixes(&self) -> &HashSet<String> {
        &self.reserved_prefixes
    }
}

/// Assembles the final set of billets for token issuance.
///
/// Algorithm:
/// 1. Start with Cedar-evaluated billets
/// 2. Remove any billet whose name starts with a reserved implicit prefix followed by ':'
/// 3. Union with implicit billets where `in_tokens = true` (from ImplicitBilletResult.token_billets)
///
/// This ensures that:
/// - Cedar policies cannot mint billets that impersonate implicit sources
/// - Implicit billets marked for token inclusion are always present
/// - The final token contains a clean union of both sources
pub fn assemble_token_billets(
    cedar_billets: &[String],
    implicit_result: &ImplicitBilletResult,
    reserved_prefixes: &HashSet<String>,
) -> Vec<String> {
    // Filter Cedar billets: remove any whose name starts with "<reserved_prefix>:"
    let filtered_cedar: Vec<String> = cedar_billets
        .iter()
        .filter(|billet| {
            !reserved_prefixes
                .iter()
                .any(|prefix| billet.starts_with(&format!("{}:", prefix)))
        })
        .cloned()
        .collect();

    // Union filtered Cedar billets with implicit token billets (in_tokens = true)
    let mut result = filtered_cedar;
    for implicit_billet in &implicit_result.token_billets {
        if !result.contains(implicit_billet) {
            result.push(implicit_billet.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::identity::{ImplicitClaimConfig, OidcSourceConfig};
    use std::time::Duration;

    fn make_oidc_source(
        prefix: &str,
        implicit_claims: Vec<ImplicitClaimConfig>,
    ) -> OidcSourceConfig {
        OidcSourceConfig {
            prefix: prefix.to_string(),
            issuer: format!("https://{}.example.com", prefix),
            client_ids: vec!["client-1".to_string()],
            jwks_refresh_interval: Duration::from_secs(3600),
            max_staleness: Duration::from_secs(86400),
            implicit_claims,
        }
    }

    fn make_implicit_claim(claim: &str, billet_prefix: &str, in_tokens: bool) -> ImplicitClaimConfig {
        ImplicitClaimConfig {
            claim: claim.to_string(),
            billet_prefix: billet_prefix.to_string(),
            in_tokens,
        }
    }

    #[test]
    fn test_from_config_empty_sources() {
        let mapper = ImplicitBilletMapper::from_config(&[]);
        assert!(mapper.mappings.is_empty());
        assert!(mapper.reserved_prefixes.is_empty());
    }

    #[test]
    fn test_from_config_no_implicit_claims() {
        let sources = vec![make_oidc_source("okta", vec![])];
        let mapper = ImplicitBilletMapper::from_config(&sources);
        assert!(mapper.mappings.is_empty());
        assert!(mapper.reserved_prefixes.is_empty());
    }

    #[test]
    fn test_from_config_single_source_with_mappings() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![
                make_implicit_claim("groups", "okta-group", false),
                make_implicit_claim("roles", "okta-role", true),
            ],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        assert_eq!(mapper.mappings.len(), 1);
        assert_eq!(mapper.mappings["okta"].len(), 2);
        assert_eq!(
            mapper.reserved_prefixes,
            HashSet::from(["okta-group".to_string(), "okta-role".to_string()])
        );
    }

    #[test]
    fn test_from_config_multiple_sources() {
        let sources = vec![
            make_oidc_source(
                "okta",
                vec![make_implicit_claim("groups", "okta-group", false)],
            ),
            make_oidc_source(
                "azuread",
                vec![make_implicit_claim("roles", "azure-role", true)],
            ),
        ];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        assert_eq!(mapper.mappings.len(), 2);
        assert!(mapper.mappings.contains_key("okta"));
        assert!(mapper.mappings.contains_key("azuread"));
        assert_eq!(
            mapper.reserved_prefixes,
            HashSet::from(["okta-group".to_string(), "azure-role".to_string()])
        );
    }

    #[test]
    fn test_derive_billets_no_mappings_for_idp() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", true)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([("groups".to_string(), vec!["eng".to_string()])]);
        let result = mapper.derive_billets("unknown-idp", &claims);

        assert!(result.token_billets.is_empty());
        assert!(result.all_billets.is_empty());
    }

    #[test]
    fn test_derive_billets_claim_not_present() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", true)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims: HashMap<String, Vec<String>> = HashMap::new();
        let result = mapper.derive_billets("okta", &claims);

        assert!(result.token_billets.is_empty());
        assert!(result.all_billets.is_empty());
    }

    #[test]
    fn test_derive_billets_in_tokens_true() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", true)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([(
            "groups".to_string(),
            vec!["engineering".to_string(), "billing-ops".to_string()],
        )]);
        let result = mapper.derive_billets("okta", &claims);

        assert_eq!(
            result.all_billets,
            vec!["okta-group:engineering", "okta-group:billing-ops"]
        );
        assert_eq!(
            result.token_billets,
            vec!["okta-group:engineering", "okta-group:billing-ops"]
        );
    }

    #[test]
    fn test_derive_billets_in_tokens_false() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", false)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([(
            "groups".to_string(),
            vec!["engineering".to_string(), "billing-ops".to_string()],
        )]);
        let result = mapper.derive_billets("okta", &claims);

        assert_eq!(
            result.all_billets,
            vec!["okta-group:engineering", "okta-group:billing-ops"]
        );
        assert!(result.token_billets.is_empty());
    }

    #[test]
    fn test_derive_billets_multiple_mappings_union() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![
                make_implicit_claim("groups", "okta-group", false),
                make_implicit_claim("roles", "okta-role", true),
            ],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([
            (
                "groups".to_string(),
                vec!["engineering".to_string(), "billing-ops".to_string()],
            ),
            ("roles".to_string(), vec!["admin".to_string()]),
        ]);
        let result = mapper.derive_billets("okta", &claims);

        assert_eq!(
            result.all_billets,
            vec![
                "okta-group:engineering",
                "okta-group:billing-ops",
                "okta-role:admin",
            ]
        );
        assert_eq!(result.token_billets, vec!["okta-role:admin"]);
    }

    #[test]
    fn test_derive_billets_example_from_spec() {
        // Config: claim="groups", billet_prefix="okta-group", in_tokens=false
        // Claims: {"groups": ["engineering", "billing-ops"]}
        // Result: all_billets=["okta-group:engineering", "okta-group:billing-ops"], token_billets=[]
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", false)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([(
            "groups".to_string(),
            vec!["engineering".to_string(), "billing-ops".to_string()],
        )]);
        let result = mapper.derive_billets("okta", &claims);

        assert_eq!(
            result.all_billets,
            vec!["okta-group:engineering", "okta-group:billing-ops"]
        );
        assert!(result.token_billets.is_empty());
    }

    #[test]
    fn test_reserved_prefixes_returns_all_configured_prefixes() {
        let sources = vec![
            make_oidc_source(
                "okta",
                vec![
                    make_implicit_claim("groups", "okta-group", false),
                    make_implicit_claim("roles", "okta-role", true),
                ],
            ),
            make_oidc_source(
                "azuread",
                vec![make_implicit_claim("groups", "azure-group", true)],
            ),
        ];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let reserved = mapper.reserved_prefixes();
        assert_eq!(reserved.len(), 3);
        assert!(reserved.contains("okta-group"));
        assert!(reserved.contains("okta-role"));
        assert!(reserved.contains("azure-group"));
    }

    #[test]
    fn test_derive_billets_empty_claim_values() {
        let sources = vec![make_oidc_source(
            "okta",
            vec![make_implicit_claim("groups", "okta-group", true)],
        )];
        let mapper = ImplicitBilletMapper::from_config(&sources);

        let claims = HashMap::from([("groups".to_string(), vec![])]);
        let result = mapper.derive_billets("okta", &claims);

        assert!(result.all_billets.is_empty());
        assert!(result.token_billets.is_empty());
    }

    // --- Tests for assemble_token_billets ---

    #[test]
    fn test_assemble_cedar_billets_no_reserved_conflicts_pass_through() {
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "infra-reader".to_string(),
        ];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes = HashSet::from(["okta-group".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert_eq!(result, vec!["billing-writer", "infra-reader"]);
    }

    #[test]
    fn test_assemble_cedar_billets_matching_reserved_prefix_are_stripped() {
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "okta-group:engineering".to_string(),
            "okta-group:billing-ops".to_string(),
            "infra-reader".to_string(),
        ];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes = HashSet::from(["okta-group".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert_eq!(result, vec!["billing-writer", "infra-reader"]);
    }

    #[test]
    fn test_assemble_implicit_token_billets_always_included() {
        let cedar_billets = vec!["billing-writer".to_string()];
        let implicit_result = ImplicitBilletResult {
            token_billets: vec![
                "okta-role:admin".to_string(),
                "okta-role:viewer".to_string(),
            ],
            all_billets: vec![
                "okta-role:admin".to_string(),
                "okta-role:viewer".to_string(),
                "okta-group:engineering".to_string(),
            ],
        };
        let reserved_prefixes = HashSet::from([
            "okta-role".to_string(),
            "okta-group".to_string(),
        ]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert_eq!(
            result,
            vec!["billing-writer", "okta-role:admin", "okta-role:viewer"]
        );
    }

    #[test]
    fn test_assemble_final_result_is_union() {
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "infra-reader".to_string(),
        ];
        let implicit_result = ImplicitBilletResult {
            token_billets: vec!["okta-role:admin".to_string()],
            all_billets: vec![
                "okta-role:admin".to_string(),
                "okta-group:engineering".to_string(),
            ],
        };
        let reserved_prefixes = HashSet::from([
            "okta-role".to_string(),
            "okta-group".to_string(),
        ]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // Cedar billets that don't match reserved prefixes + implicit token_billets
        assert_eq!(
            result,
            vec!["billing-writer", "infra-reader", "okta-role:admin"]
        );
    }

    #[test]
    fn test_assemble_empty_cedar_billets() {
        let cedar_billets: Vec<String> = vec![];
        let implicit_result = ImplicitBilletResult {
            token_billets: vec!["okta-role:admin".to_string()],
            all_billets: vec!["okta-role:admin".to_string()],
        };
        let reserved_prefixes = HashSet::from(["okta-role".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert_eq!(result, vec!["okta-role:admin"]);
    }

    #[test]
    fn test_assemble_empty_implicit_billets() {
        let cedar_billets = vec!["billing-writer".to_string()];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes = HashSet::from(["okta-group".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert_eq!(result, vec!["billing-writer"]);
    }

    #[test]
    fn test_assemble_empty_reserved_prefixes() {
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "okta-group:engineering".to_string(),
        ];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes: HashSet<String> = HashSet::new();

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // No reserved prefixes, so nothing is stripped
        assert_eq!(result, vec!["billing-writer", "okta-group:engineering"]);
    }

    #[test]
    fn test_assemble_all_empty() {
        let cedar_billets: Vec<String> = vec![];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes: HashSet<String> = HashSet::new();

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        assert!(result.is_empty());
    }

    #[test]
    fn test_assemble_prefix_match_requires_colon_separator() {
        // Prefix "a" should match "a:value" but NOT "ab:value"
        let cedar_billets = vec![
            "a:value".to_string(),
            "ab:value".to_string(),
            "abc:value".to_string(),
        ];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes = HashSet::from(["a".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // Only "a:value" should be stripped; "ab:value" and "abc:value" remain
        assert_eq!(result, vec!["ab:value", "abc:value"]);
    }

    #[test]
    fn test_assemble_prefix_okta_does_not_match_oktagonal() {
        // Prefix "okta" should match "okta:billing" but NOT "oktagonal-team"
        let cedar_billets = vec![
            "okta:billing".to_string(),
            "oktagonal-team".to_string(),
            "okta:admin".to_string(),
        ];
        let implicit_result = ImplicitBilletResult::default();
        let reserved_prefixes = HashSet::from(["okta".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // "okta:billing" and "okta:admin" are stripped; "oktagonal-team" passes through
        assert_eq!(result, vec!["oktagonal-team"]);
    }

    #[test]
    fn test_assemble_no_duplicate_when_implicit_already_in_cedar() {
        // If an implicit token billet also appears in the Cedar result (shouldn't happen
        // due to prefix stripping, but guard against it), ensure no duplicate in output
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "okta-role:admin".to_string(), // This would be stripped by prefix
        ];
        let implicit_result = ImplicitBilletResult {
            token_billets: vec!["billing-writer".to_string()], // Same as a Cedar billet
            all_billets: vec!["billing-writer".to_string()],
        };
        let reserved_prefixes = HashSet::from(["okta-role".to_string()]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // "billing-writer" should appear once (from Cedar), not duplicated
        assert_eq!(result, vec!["billing-writer"]);
    }

    #[test]
    fn test_assemble_multiple_reserved_prefixes() {
        let cedar_billets = vec![
            "billing-writer".to_string(),
            "okta-group:engineering".to_string(),
            "azure-role:contributor".to_string(),
            "infra-reader".to_string(),
        ];
        let implicit_result = ImplicitBilletResult {
            token_billets: vec!["okta-role:admin".to_string()],
            all_billets: vec!["okta-role:admin".to_string()],
        };
        let reserved_prefixes = HashSet::from([
            "okta-group".to_string(),
            "azure-role".to_string(),
            "okta-role".to_string(),
        ]);

        let result = super::assemble_token_billets(&cedar_billets, &implicit_result, &reserved_prefixes);

        // Stripped: "okta-group:engineering", "azure-role:contributor"
        // Kept from Cedar: "billing-writer", "infra-reader"
        // Added from implicit: "okta-role:admin"
        assert_eq!(result, vec!["billing-writer", "infra-reader", "okta-role:admin"]);
    }
}
