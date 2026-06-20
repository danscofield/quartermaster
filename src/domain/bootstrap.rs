use crate::datastore::{BilletRecord, DataStore, DataStoreError};

/// System billet definitions for bootstrap.
struct SystemBillet {
    name: &'static str,
    description: &'static str,
}

const SYSTEM_BILLETS: &[SystemBillet] = &[
    SystemBillet {
        name: "quartermaster-guardrails",
        description: "System billet for global guardrail (forbid) policies",
    },
    SystemBillet {
        name: "quartermaster-admin",
        description: "Bootstrap admin billet",
    },
];

/// Idempotently creates the required system billets (`quartermaster-guardrails` and
/// `quartermaster-admin`) if they do not already exist.
///
/// For each system billet, this function calls `get_billet`. If the billet is
/// absent, it creates one with the expected description, tags `["system:true"]`, and
/// empty role/SA lists. If the billet already exists, no action is taken.
pub async fn bootstrap_system_billets(
    data_store: &dyn DataStore,
) -> Result<(), DataStoreError> {
    for billet in SYSTEM_BILLETS {
        let existing = data_store.get_billet(billet.name).await?;
        if existing.is_none() {
            let now = chrono::Utc::now().to_rfc3339();
            let record = BilletRecord {
                name: billet.name.to_string(),
                description: billet.description.to_string(),
                associated_aws_roles: vec![],
                associated_gcp_sas: vec![],
                tags: vec!["system:true".to_string()],
                created_at: now.clone(),
                updated_at: now,
            };
            data_store.create_billet(&record).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::MockDataStore;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_creates_both_billets_when_neither_exists() {
        let mut mock = MockDataStore::new();

        mock.expect_get_billet()
            .with(eq("quartermaster-guardrails"))
            .times(1)
            .returning(|_| Ok(None));

        mock.expect_create_billet()
            .withf(|r| {
                r.name == "quartermaster-guardrails"
                    && r.description == "System billet for global guardrail (forbid) policies"
                    && r.tags == vec!["system:true".to_string()]
                    && r.associated_aws_roles.is_empty()
                    && r.associated_gcp_sas.is_empty()
            })
            .times(1)
            .returning(|_| Ok(()));

        mock.expect_get_billet()
            .with(eq("quartermaster-admin"))
            .times(1)
            .returning(|_| Ok(None));

        mock.expect_create_billet()
            .withf(|r| {
                r.name == "quartermaster-admin"
                    && r.description == "Bootstrap admin billet"
                    && r.tags == vec!["system:true".to_string()]
                    && r.associated_aws_roles.is_empty()
                    && r.associated_gcp_sas.is_empty()
            })
            .times(1)
            .returning(|_| Ok(()));

        let result = bootstrap_system_billets(&mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_idempotent_when_both_already_exist() {
        let mut mock = MockDataStore::new();

        mock.expect_get_billet()
            .with(eq("quartermaster-guardrails"))
            .times(1)
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "quartermaster-guardrails".to_string(),
                    description: "System billet for global guardrail (forbid) policies".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec!["system:true".to_string()],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });

        mock.expect_get_billet()
            .with(eq("quartermaster-admin"))
            .times(1)
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "quartermaster-admin".to_string(),
                    description: "Bootstrap admin billet".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec!["system:true".to_string()],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });

        // create_billet should NOT be called
        mock.expect_create_billet().times(0);

        let result = bootstrap_system_billets(&mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_creates_only_missing_billet() {
        let mut mock = MockDataStore::new();

        // quartermaster-guardrails already exists
        mock.expect_get_billet()
            .with(eq("quartermaster-guardrails"))
            .times(1)
            .returning(|_| {
                Ok(Some(BilletRecord {
                    name: "quartermaster-guardrails".to_string(),
                    description: "System billet for global guardrail (forbid) policies".to_string(),
                    associated_aws_roles: vec![],
                    associated_gcp_sas: vec![],
                    tags: vec!["system:true".to_string()],
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }))
            });

        // quartermaster-admin does NOT exist
        mock.expect_get_billet()
            .with(eq("quartermaster-admin"))
            .times(1)
            .returning(|_| Ok(None));

        // Only quartermaster-admin should be created
        mock.expect_create_billet()
            .withf(|r| r.name == "quartermaster-admin")
            .times(1)
            .returning(|_| Ok(()));

        let result = bootstrap_system_billets(&mock).await;
        assert!(result.is_ok());
    }
}
