use super::AuthenticatedIdentity;

/// Formats the `sub` claim for a Quartermaster JWT based on the identity source type.
///
/// - SPIRE → the literal SPIFFE ID
/// - OIDC → `human:<email>`
/// - AWS STS → `aws:<account_id>:<role_name>`
/// - GCP → `gcp:<project_id>:<email>`
pub fn format_subject(identity: &AuthenticatedIdentity) -> String {
    match identity {
        AuthenticatedIdentity::Spire(spire) => spire.spiffe_id.clone(),
        AuthenticatedIdentity::Oidc(oidc) => format!("human:{}", oidc.email),
        AuthenticatedIdentity::AwsSts(aws) => {
            format!("aws:{}:{}", aws.account_id, aws.role_name)
        }
        AuthenticatedIdentity::Gcp(gcp) => {
            format!("gcp:{}:{}", gcp.project_id, gcp.email)
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
    fn test_spire_subject_is_spiffe_id() {
        let identity = AuthenticatedIdentity::Spire(SpireIdentity {
            spiffe_id: "spiffe://example.com/ns/finance/workload/payments".into(),
            trust_domain: "example.com".into(),
            environment: "production".into(),
            region: "us-east-1".into(),
            audience: vec!["quartermaster".into()],
        });
        assert_eq!(
            format_subject(&identity),
            "spiffe://example.com/ns/finance/workload/payments"
        );
    }

    #[test]
    fn test_oidc_subject_format() {
        let identity = AuthenticatedIdentity::Oidc(OidcIdentity {
            email: "alice@corp.example.com".into(),
            idp_prefix: "okta".into(),
            claims: HashMap::new(),
            subject: "auth0|12345".into(),
        });
        assert_eq!(format_subject(&identity), "human:alice@corp.example.com");
    }

    #[test]
    fn test_aws_sts_subject_format() {
        let identity = AuthenticatedIdentity::AwsSts(AwsStsIdentity {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/billing-service".into(),
            role_name: "billing-service".into(),
            role_path: "/".into(),
            session_name: "session-abc".into(),
        });
        assert_eq!(
            format_subject(&identity),
            "aws:123456789012:billing-service"
        );
    }

    #[test]
    fn test_gcp_subject_format() {
        let identity = AuthenticatedIdentity::Gcp(GcpIdentity {
            project_id: "my-project".into(),
            email: "sa@proj.iam.gserviceaccount.com".into(),
            zone: "us-central1-a".into(),
            unique_id: "112233445566".into(),
        });
        assert_eq!(
            format_subject(&identity),
            "gcp:my-project:sa@proj.iam.gserviceaccount.com"
        );
    }
}
