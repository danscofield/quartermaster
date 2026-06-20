// Platform detection + ephemeral entity construction

use crate::cedar::{PlatformType, WorkloadEntity};

/// Input parameters for constructing a WorkloadEntity.
#[derive(Debug, Clone)]
pub struct EntityBuilderInput {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub environment: String,
    pub region: String,
    pub selectors: Vec<String>,
}

/// EntityBuilder detects the workload platform from SPIRE selectors and constructs
/// the appropriate typed WorkloadEntity with platform-specific attributes extracted
/// from selectors.
///
/// Platform detection uses priority order:
/// 1. If ANY selector prefixed with `k8s:` → K8sWorkload (highest priority)
/// 2. Else if ANY selector prefixed with `aws:` → Ec2Workload
/// 3. Else if ANY selector prefixed with `gcp:` → GcpWorkload
/// 4. Else → base Workload
pub struct EntityBuilder;

impl EntityBuilder {
    /// Constructs a new EntityBuilder.
    pub fn new() -> Self {
        Self
    }

    /// Builds a WorkloadEntity from the given input, detecting platform type
    /// and extracting platform-specific attributes from selectors.
    pub fn build(&self, input: EntityBuilderInput) -> WorkloadEntity {
        let platform = Self::detect_platform(&input.selectors);

        let mut entity = WorkloadEntity {
            entity_type: platform.clone(),
            spiffe_id: input.spiffe_id,
            trust_domain: input.trust_domain,
            environment: input.environment,
            region: input.region,
            selectors: input.selectors.clone(),
            namespace: None,
            service_account: None,
            pod_labels: Vec::new(),
            container_name: None,
            node_name: None,
            instance_id: None,
            account_id: None,
            ami_id: None,
            instance_tags: Vec::new(),
            security_groups: Vec::new(),
            project_id: None,
            zone: None,
            service_account_email: None,
            instance_name: None,
        };

        match platform {
            PlatformType::K8s => Self::extract_k8s_attributes(&input.selectors, &mut entity),
            PlatformType::Ec2 => Self::extract_ec2_attributes(&input.selectors, &mut entity),
            PlatformType::Gcp => Self::extract_gcp_attributes(&input.selectors, &mut entity),
            PlatformType::Base => {}
        }

        entity
    }

    /// Detects the platform type from selector prefixes using priority order.
    fn detect_platform(selectors: &[String]) -> PlatformType {
        let has_k8s = selectors.iter().any(|s| s.starts_with("k8s:"));
        if has_k8s {
            return PlatformType::K8s;
        }

        let has_aws = selectors.iter().any(|s| s.starts_with("aws:"));
        if has_aws {
            return PlatformType::Ec2;
        }

        let has_gcp = selectors.iter().any(|s| s.starts_with("gcp:"));
        if has_gcp {
            return PlatformType::Gcp;
        }

        PlatformType::Base
    }

    /// Extracts Kubernetes-specific attributes from selectors.
    ///
    /// Selector formats:
    /// - `k8s:ns:<value>` → namespace
    /// - `k8s:sa:<value>` → service_account
    /// - `k8s:pod-label:<key>:<value>` → pod_labels (stored as "key:value")
    /// - `k8s:container-name:<value>` → container_name
    /// - `k8s:node-name:<value>` → node_name
    fn extract_k8s_attributes(selectors: &[String], entity: &mut WorkloadEntity) {
        for selector in selectors {
            if let Some(value) = selector.strip_prefix("k8s:ns:") {
                entity.namespace = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("k8s:sa:") {
                entity.service_account = Some(value.to_string());
            } else if let Some(rest) = selector.strip_prefix("k8s:pod-label:") {
                // Format: k8s:pod-label:<key>:<value> → stored as "key:value"
                entity.pod_labels.push(rest.to_string());
            } else if let Some(value) = selector.strip_prefix("k8s:container-name:") {
                entity.container_name = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("k8s:node-name:") {
                entity.node_name = Some(value.to_string());
            }
        }
    }

    /// Extracts EC2-specific attributes from selectors.
    ///
    /// Selector formats:
    /// - `aws:iid:instance-id:<value>` → instance_id
    /// - `aws:iid:account-id:<value>` → account_id
    /// - `aws:iid:image-id:<value>` → ami_id
    /// - `aws:iid:instance-tag:<key>:<value>` → instance_tags (stored as "key:value")
    /// - `aws:iid:security-group-id:<value>` → security_groups
    fn extract_ec2_attributes(selectors: &[String], entity: &mut WorkloadEntity) {
        for selector in selectors {
            if let Some(value) = selector.strip_prefix("aws:iid:instance-id:") {
                entity.instance_id = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("aws:iid:account-id:") {
                entity.account_id = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("aws:iid:image-id:") {
                entity.ami_id = Some(value.to_string());
            } else if let Some(rest) = selector.strip_prefix("aws:iid:instance-tag:") {
                // Format: aws:iid:instance-tag:<key>:<value> → stored as "key:value"
                entity.instance_tags.push(rest.to_string());
            } else if let Some(value) = selector.strip_prefix("aws:iid:security-group-id:") {
                entity.security_groups.push(value.to_string());
            }
        }
    }

    /// Extracts GCP-specific attributes from selectors.
    ///
    /// Selector formats:
    /// - `gcp:iit:project-id:<value>` → project_id
    /// - `gcp:iit:zone:<value>` → zone
    /// - `gcp:iit:service-account:<value>` → service_account_email
    /// - `gcp:iit:instance-name:<value>` → instance_name
    fn extract_gcp_attributes(selectors: &[String], entity: &mut WorkloadEntity) {
        for selector in selectors {
            if let Some(value) = selector.strip_prefix("gcp:iit:project-id:") {
                entity.project_id = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("gcp:iit:zone:") {
                entity.zone = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("gcp:iit:service-account:") {
                entity.service_account_email = Some(value.to_string());
            } else if let Some(value) = selector.strip_prefix("gcp:iit:instance-name:") {
                entity.instance_name = Some(value.to_string());
            }
        }
    }
}

impl Default for EntityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(selectors: Vec<&str>) -> EntityBuilderInput {
        EntityBuilderInput {
            spiffe_id: "spiffe://example.org/ns/finance/workload/payments".to_string(),
            trust_domain: "example.org".to_string(),
            environment: "production".to_string(),
            region: "us-east-1".to_string(),
            selectors: selectors.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn test_detect_k8s_platform() {
        let input = make_input(vec![
            "k8s:ns:finance",
            "k8s:sa:payments-sa",
            "k8s:pod-label:project:payments",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::K8s);
    }

    #[test]
    fn test_detect_ec2_platform() {
        let input = make_input(vec![
            "aws:iid:instance-id:i-1234567890abcdef0",
            "aws:iid:account-id:123456789012",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::Ec2);
    }

    #[test]
    fn test_detect_gcp_platform() {
        let input = make_input(vec![
            "gcp:iit:project-id:my-project",
            "gcp:iit:zone:us-central1-a",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::Gcp);
    }

    #[test]
    fn test_detect_base_platform_no_selectors() {
        let input = make_input(vec![]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::Base);
    }

    #[test]
    fn test_detect_base_platform_unknown_selectors() {
        let input = make_input(vec!["custom:foo:bar", "other:thing"]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::Base);
    }

    #[test]
    fn test_k8s_priority_over_aws() {
        // Mixed selectors: k8s has highest priority (EKS scenario)
        let input = make_input(vec![
            "k8s:ns:finance",
            "aws:iid:instance-id:i-123",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::K8s);
    }

    #[test]
    fn test_k8s_priority_over_gcp() {
        let input = make_input(vec![
            "k8s:ns:finance",
            "gcp:iit:project-id:my-project",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::K8s);
    }

    #[test]
    fn test_aws_priority_over_gcp() {
        let input = make_input(vec![
            "aws:iid:instance-id:i-123",
            "gcp:iit:project-id:my-project",
        ]);
        let entity = EntityBuilder::new().build(input);
        assert_eq!(entity.entity_type, PlatformType::Ec2);
    }

    #[test]
    fn test_k8s_attribute_extraction() {
        let input = make_input(vec![
            "k8s:ns:finance",
            "k8s:sa:payments-sa",
            "k8s:pod-label:project:payments",
            "k8s:pod-label:team:billing",
            "k8s:container-name:payments-app",
            "k8s:node-name:node-1",
        ]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::K8s);
        assert_eq!(entity.namespace, Some("finance".to_string()));
        assert_eq!(entity.service_account, Some("payments-sa".to_string()));
        assert_eq!(entity.pod_labels, vec!["project:payments", "team:billing"]);
        assert_eq!(entity.container_name, Some("payments-app".to_string()));
        assert_eq!(entity.node_name, Some("node-1".to_string()));
    }

    #[test]
    fn test_ec2_attribute_extraction() {
        let input = make_input(vec![
            "aws:iid:instance-id:i-1234567890abcdef0",
            "aws:iid:account-id:123456789012",
            "aws:iid:image-id:ami-12345678",
            "aws:iid:instance-tag:env:production",
            "aws:iid:instance-tag:project:payments",
            "aws:iid:security-group-id:sg-12345",
            "aws:iid:security-group-id:sg-67890",
        ]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::Ec2);
        assert_eq!(entity.instance_id, Some("i-1234567890abcdef0".to_string()));
        assert_eq!(entity.account_id, Some("123456789012".to_string()));
        assert_eq!(entity.ami_id, Some("ami-12345678".to_string()));
        assert_eq!(entity.instance_tags, vec!["env:production", "project:payments"]);
        assert_eq!(entity.security_groups, vec!["sg-12345", "sg-67890"]);
    }

    #[test]
    fn test_gcp_attribute_extraction() {
        let input = make_input(vec![
            "gcp:iit:project-id:my-project",
            "gcp:iit:zone:us-central1-a",
            "gcp:iit:service-account:sa@my-project.iam.gserviceaccount.com",
            "gcp:iit:instance-name:my-instance",
        ]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::Gcp);
        assert_eq!(entity.project_id, Some("my-project".to_string()));
        assert_eq!(entity.zone, Some("us-central1-a".to_string()));
        assert_eq!(
            entity.service_account_email,
            Some("sa@my-project.iam.gserviceaccount.com".to_string())
        );
        assert_eq!(entity.instance_name, Some("my-instance".to_string()));
    }

    #[test]
    fn test_common_attributes_populated() {
        let input = make_input(vec!["k8s:ns:finance"]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.spiffe_id, "spiffe://example.org/ns/finance/workload/payments");
        assert_eq!(entity.trust_domain, "example.org");
        assert_eq!(entity.environment, "production");
        assert_eq!(entity.region, "us-east-1");
        assert_eq!(entity.selectors, vec!["k8s:ns:finance"]);
    }

    #[test]
    fn test_all_selectors_preserved_regardless_of_platform() {
        // Per requirement 27.8: ALL selectors included regardless of platform
        let input = make_input(vec![
            "k8s:ns:finance",
            "aws:iid:instance-id:i-123",
            "gcp:iit:project-id:proj",
            "custom:foo:bar",
        ]);
        let entity = EntityBuilder::new().build(input);

        // K8s has highest priority
        assert_eq!(entity.entity_type, PlatformType::K8s);
        // But all selectors are preserved
        assert_eq!(entity.selectors.len(), 4);
        assert!(entity.selectors.contains(&"k8s:ns:finance".to_string()));
        assert!(entity.selectors.contains(&"aws:iid:instance-id:i-123".to_string()));
        assert!(entity.selectors.contains(&"gcp:iit:project-id:proj".to_string()));
        assert!(entity.selectors.contains(&"custom:foo:bar".to_string()));
    }

    #[test]
    fn test_k8s_partial_attributes() {
        // Only some K8s attributes present
        let input = make_input(vec!["k8s:ns:default"]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::K8s);
        assert_eq!(entity.namespace, Some("default".to_string()));
        assert_eq!(entity.service_account, None);
        assert!(entity.pod_labels.is_empty());
        assert_eq!(entity.container_name, None);
        assert_eq!(entity.node_name, None);
    }

    #[test]
    fn test_ec2_partial_attributes() {
        let input = make_input(vec!["aws:iid:instance-id:i-abc"]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::Ec2);
        assert_eq!(entity.instance_id, Some("i-abc".to_string()));
        assert_eq!(entity.account_id, None);
        assert_eq!(entity.ami_id, None);
        assert!(entity.instance_tags.is_empty());
        assert!(entity.security_groups.is_empty());
    }

    #[test]
    fn test_gcp_partial_attributes() {
        let input = make_input(vec!["gcp:iit:zone:us-east1-b"]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::Gcp);
        assert_eq!(entity.project_id, None);
        assert_eq!(entity.zone, Some("us-east1-b".to_string()));
        assert_eq!(entity.service_account_email, None);
        assert_eq!(entity.instance_name, None);
    }

    #[test]
    fn test_base_entity_has_no_platform_attributes() {
        let input = make_input(vec!["custom:selector:value"]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.entity_type, PlatformType::Base);
        assert_eq!(entity.namespace, None);
        assert_eq!(entity.service_account, None);
        assert!(entity.pod_labels.is_empty());
        assert_eq!(entity.container_name, None);
        assert_eq!(entity.node_name, None);
        assert_eq!(entity.instance_id, None);
        assert_eq!(entity.account_id, None);
        assert_eq!(entity.ami_id, None);
        assert!(entity.instance_tags.is_empty());
        assert!(entity.security_groups.is_empty());
        assert_eq!(entity.project_id, None);
        assert_eq!(entity.zone, None);
        assert_eq!(entity.service_account_email, None);
        assert_eq!(entity.instance_name, None);
    }

    #[test]
    fn test_last_value_wins_for_singular_k8s_attributes() {
        // If multiple selectors set the same singular attribute, last one wins
        let input = make_input(vec![
            "k8s:ns:first",
            "k8s:ns:second",
        ]);
        let entity = EntityBuilder::new().build(input);

        assert_eq!(entity.namespace, Some("second".to_string()));
    }

    #[test]
    fn test_default_impl() {
        let builder = EntityBuilder::default();
        let input = make_input(vec![]);
        let entity = builder.build(input);
        assert_eq!(entity.entity_type, PlatformType::Base);
    }
}
