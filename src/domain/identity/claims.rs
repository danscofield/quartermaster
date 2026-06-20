use serde_json::{json, Value};

use super::AuthenticatedIdentity;

/// Builds the `identity` claim for a Quartermaster JWT based on the identity source type.
///
/// The returned JSON object always includes a `type` field plus source-specific fields:
/// - SPIRE → `type: "workload"`, `spiffe_id`
/// - OIDC → `type: "human"`, `email`, `idp`, `groups` (flattened union of all claim values)
/// - AWS STS → `type: "aws_role"`, `account_id`, `role_arn`
/// - GCP → `type: "gcp_workload"`, `project_id`, `email`
pub fn build_identity_claim(identity: &AuthenticatedIdentity) -> Value {
    match identity {
        AuthenticatedIdentity::Spire(spire) => {
            json!({
                "type": "workload",
                "spiffe_id": spire.spiffe_id,
            })
        }
        AuthenticatedIdentity::Oidc(oidc) => {
            // Flatten all claim values into a single groups list (union of all values)
            let groups: Vec<&str> = oidc
                .claims
                .values()
                .flat_map(|values| values.iter().map(|s| s.as_str()))
                .collect();

            json!({
                "type": "human",
                "email": oidc.email,
                "idp": oidc.idp_prefix,
                "groups": groups,
            })
        }
        AuthenticatedIdentity::AwsSts(aws) => {
            json!({
                "type": "aws_role",
                "account_id": aws.account_id,
                "role_arn": aws.role_arn,
            })
        }
        AuthenticatedIdentity::Gcp(gcp) => {
            json!({
                "type": "gcp_workload",
                "project_id": gcp.project_id,
                "email": gcp.email,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::identity::{
        AwsStsIdentity, GcpIdentity, OidcIdentity, SpireIdentity,
    };
    use std::collections::HashMap;

    #[test]
    fn test_spire_identity_claim() {
        let identity = AuthenticatedIdentity::Spire(SpireIdentity {
            spiffe_id: "spiffe://example.com/ns/finance/workload/payments".into(),
            trust_domain: "example.com".into(),
            environment: "production".into(),
            region: "us-east-1".into(),
            audience: vec!["quartermaster".into()],
        });

        let claim = build_identity_claim(&identity);
        assert_eq!(claim["type"], "workload");
        assert_eq!(
            claim["spiffe_id"],
            "spiffe://example.com/ns/finance/workload/payments"
        );
    }

    #[test]
    fn test_oidc_identity_claim() {
        let identity = AuthenticatedIdentity::Oidc(OidcIdentity {
            email: "alice@corp.example.com".into(),
            idp_prefix: "okta".into(),
            claims: HashMap::from([
                (
                    "groups".into(),
                    vec!["billing-ops".into(), "engineering".into()],
                ),
                ("roles".into(), vec!["admin".into()]),
            ]),
            subject: "auth0|12345".into(),
        });

        let claim = build_identity_claim(&identity);
        assert_eq!(claim["type"], "human");
        assert_eq!(claim["email"], "alice@corp.example.com");
        assert_eq!(claim["idp"], "okta");

        // groups is the flattened union of all claim values
        let groups = claim["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 3);
        let groups_str: Vec<&str> = groups.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(groups_str.contains(&"billing-ops"));
        assert!(groups_str.contains(&"engineering"));
        assert!(groups_str.contains(&"admin"));
    }

    #[test]
    fn test_oidc_identity_claim_empty_claims() {
        let identity = AuthenticatedIdentity::Oidc(OidcIdentity {
            email: "bob@example.com".into(),
            idp_prefix: "azure".into(),
            claims: HashMap::new(),
            subject: "sub-xyz".into(),
        });

        let claim = build_identity_claim(&identity);
        assert_eq!(claim["type"], "human");
        assert_eq!(claim["email"], "bob@example.com");
        assert_eq!(claim["idp"], "azure");
        assert_eq!(claim["groups"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_aws_sts_identity_claim() {
        let identity = AuthenticatedIdentity::AwsSts(AwsStsIdentity {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/billing-service".into(),
            role_name: "billing-service".into(),
            role_path: "/".into(),
            session_name: "session-abc".into(),
        });

        let claim = build_identity_claim(&identity);
        assert_eq!(claim["type"], "aws_role");
        assert_eq!(claim["account_id"], "123456789012");
        assert_eq!(
            claim["role_arn"],
            "arn:aws:iam::123456789012:role/billing-service"
        );
    }

    #[test]
    fn test_gcp_identity_claim() {
        let identity = AuthenticatedIdentity::Gcp(GcpIdentity {
            project_id: "my-project".into(),
            email: "sa@my-project.iam.gserviceaccount.com".into(),
            zone: "us-central1-a".into(),
            unique_id: "112233445566".into(),
        });

        let claim = build_identity_claim(&identity);
        assert_eq!(claim["type"], "gcp_workload");
        assert_eq!(claim["project_id"], "my-project");
        assert_eq!(claim["email"], "sa@my-project.iam.gserviceaccount.com");
    }
}
