use std::io::Read;
use std::process;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::PolicySet;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use quartermaster::config::Config;
use quartermaster::datastore::{DataStore, PolicyRecord};
use quartermaster::keymanager::KeyManager;

/// CLI error type that wraps all failure modes for the bootstrap tool.
#[derive(Debug)]
pub enum CliError {
    /// Configuration loading failed
    ConfigError(String),
    /// DataStore operation failed
    DataStoreError(String),
    /// Cedar parsing failed
    CedarParseError(String),
    /// Billet not found
    BilletNotFound(String),
    /// Key/signing error
    SigningError(String),
    /// I/O error (reading stdin/file)
    IoError(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::ConfigError(msg) => write!(f, "config error: {}", msg),
            CliError::DataStoreError(msg) => write!(f, "datastore error: {}", msg),
            CliError::CedarParseError(msg) => write!(f, "cedar parse error: {}", msg),
            CliError::BilletNotFound(msg) => write!(f, "billet not found: {}", msg),
            CliError::SigningError(msg) => write!(f, "signing error: {}", msg),
            CliError::IoError(msg) => write!(f, "io error: {}", msg),
        }
    }
}

#[derive(Parser)]
#[command(name = "qm-bootstrap", about = "Quartermaster bootstrap CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a Cedar policy to a billet (from file or stdin)
    AddPolicy {
        /// Target billet name
        billet: String,
        /// Path to Cedar policy file, or "-" for stdin
        source: String,
    },
    /// List all billets
    ListBillets,
    /// List policies for a billet
    ListPolicies {
        /// Billet name
        billet: String,
    },
    /// Issue a short-lived admin JWT
    IssueToken {
        /// One or more billet names to include in the token
        billets: Vec<String>,
    },
}


#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // For --help and --version, print to stdout and exit 0
            // For usage errors (missing/unknown subcommand), print to stderr and exit 1
            if e.use_stderr() {
                let _ = e.print();
                process::exit(1);
            } else {
                let _ = e.print();
                process::exit(0);
            }
        }
    };

    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    // Load configuration from QM_CONFIG_PATH
    let config = Config::load().map_err(|e| CliError::ConfigError(e.message))?;

    // Build DataStore from config
    let data_store = build_datastore(&config).await?;

    // Dispatch to subcommand handler
    match cli.command {
        Commands::AddPolicy { billet, source } => {
            add_policy(data_store.as_ref(), &billet, &source).await
        }
        Commands::ListBillets => list_billets(data_store.as_ref()).await,
        Commands::ListPolicies { billet } => list_policies(data_store.as_ref(), &billet).await,
        Commands::IssueToken { billets } => {
            let key_manager = build_key_manager(&config, Arc::clone(&data_store)).await?;
            issue_token(key_manager.as_ref(), &config, &billets).await
        }
    }
}

/// Build a DataStore from the loaded configuration.
async fn build_datastore(config: &Config) -> Result<Arc<dyn DataStore>, CliError> {
    if let Some(ref ds_config) = config.datastore {
        quartermaster::datastore::factory::build_datastore(ds_config)
            .await
            .map_err(|e| CliError::DataStoreError(e))
    } else if let Some(ref dynamo_config) = config.dynamo {
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(dynamo_config.region.clone()))
            .load()
            .await;
        Ok(Arc::new(
            quartermaster::datastore::dynamodb::DynamoDataStore::new(
                &quartermaster::config::backends::DynamoDbConfig {
                    region: dynamo_config.region.clone(),
                    billets_table: dynamo_config.billets_table.clone(),
                    policies_table: dynamo_config.policies_table.clone(),
                },
                &aws_config,
            ),
        ))
    } else {
        Err(CliError::ConfigError(
            "either [datastore] or [dynamo] section must be present in config".to_string(),
        ))
    }
}

/// Build a KeyManager from the loaded configuration (used for issue-token).
async fn build_key_manager(
    config: &Config,
    data_store: Arc<dyn DataStore>,
) -> Result<Arc<dyn KeyManager>, CliError> {
    if let Some(ref sb_config) = config.signing_backend {
        quartermaster::keymanager::factory::build_key_manager(sb_config, data_store, "signing")
            .await
            .map_err(|e| CliError::SigningError(e))
    } else {
        // Legacy fallback: build MemoryKeyManager from [signing] section
        let mem_config = quartermaster::config::backends::MemorySigningConfig {
            key_path: config.signing.key_path.to_str().unwrap_or("").to_string(),
        };
        let manager = quartermaster::keymanager::memory::MemoryKeyManager::new(&mem_config)
            .map_err(|e| CliError::SigningError(format!("failed to load signing key: {}", e)))?;
        Ok(Arc::new(manager))
    }
}

// ─── Source Reading ─────────────────────────────────────────────────────────

/// Read a Cedar policy statement from a file path or stdin.
/// When `source` is `"-"`, reads from stdin; otherwise reads the file at `source`.
fn read_source(source: &str) -> Result<String, CliError> {
    if source == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::IoError(format!("failed to read stdin: {}", e)))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(source)
            .map_err(|e| CliError::IoError(format!("failed to read '{}': {}", source, e)))
    }
}

// ─── Cedar Validation ───────────────────────────────────────────────────────

/// Validate that a string is syntactically valid Cedar policy.
/// Uses `cedar_policy::PolicySet::from_str` to parse the statement.
/// Returns `Ok(())` if valid, or `CliError::CedarParseError` with a descriptive message if invalid.
fn validate_cedar_syntax(statement: &str) -> Result<(), CliError> {
    PolicySet::from_str(statement)
        .map(|_| ())
        .map_err(|e| CliError::CedarParseError(format!("invalid Cedar syntax: {}", e)))
}

// ─── Subcommand Handlers (stubs for now, implemented in later tasks) ───────

async fn add_policy(
    data_store: &dyn DataStore,
    billet: &str,
    source: &str,
) -> Result<(), CliError> {
    // 1. Read Cedar statement from file or stdin
    let statement = read_source(source)?;
    // 2. Parse and validate Cedar syntax (reject invalid)
    validate_cedar_syntax(&statement)?;
    // 3. Verify billet exists
    let billet_record = data_store
        .get_billet(billet)
        .await
        .map_err(|e| CliError::DataStoreError(e.to_string()))?;
    if billet_record.is_none() {
        return Err(CliError::BilletNotFound(billet.to_string()));
    }
    // 4. Generate UUID, build PolicyRecord, write to DataStore
    let policy_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let record = PolicyRecord {
        billet_name: billet.to_string(),
        policy_id: policy_id.clone(),
        statement,
        description: String::new(),
        created_at: now.clone(),
        updated_at: now,
    };
    data_store
        .create_policy(&record)
        .await
        .map_err(|e| CliError::DataStoreError(e.to_string()))?;
    // 5. Print policy_id to stdout
    println!("{}", policy_id);
    Ok(())
}

async fn list_billets(data_store: &dyn DataStore) -> Result<(), CliError> {
    let billets = data_store
        .list_billets()
        .await
        .map_err(|e| CliError::DataStoreError(e.to_string()))?;
    if billets.is_empty() {
        println!("no billets found");
    } else {
        for b in billets {
            println!("{} — {}", b.name, b.description);
        }
    }
    Ok(())
}

async fn list_policies(data_store: &dyn DataStore, billet: &str) -> Result<(), CliError> {
    let policies = data_store
        .list_policies_for_billet(billet)
        .await
        .map_err(|e| CliError::DataStoreError(e.to_string()))?;
    if policies.is_empty() {
        println!("no policies found for '{}'", billet);
    } else {
        for p in policies {
            let first_line = p.statement.lines().next().unwrap_or("(empty)");
            println!("[{}] {}", p.policy_id, first_line);
        }
    }
    Ok(())
}

/// Build JWT claims for the bootstrap admin token.
///
/// Sets: iss = config.issuer, sub = "bootstrap:admin", aud = config.issuer,
/// billets = input billets, exp = now + 600 seconds, jti = UUID v4.
fn build_bootstrap_claims(
    config: &Config,
    billets: &[String],
) -> quartermaster::domain::token::Claims {
    let now = chrono::Utc::now().timestamp() as u64;
    quartermaster::domain::token::Claims {
        iss: config.issuer.clone(),
        sub: "bootstrap:admin".to_string(),
        aud: config.issuer.clone(),
        amr: billets.to_vec(),
        billets: billets.to_vec(),
        iat: now,
        exp: now + 600,
        jti: Uuid::new_v4().to_string(),
        identity: None,
    }
}

/// Sign a Claims struct into a JWT string using the KeyManager.
fn sign_jwt(
    key_manager: &dyn KeyManager,
    claims: &quartermaster::domain::token::Claims,
) -> Result<String, CliError> {
    let header = key_manager.header().clone();
    let encoding_key = key_manager.encoding_key();
    jsonwebtoken::encode(&header, claims, encoding_key)
        .map_err(|e| CliError::SigningError(format!("JWT signing failed: {}", e)))
}

async fn issue_token(
    key_manager: &dyn KeyManager,
    config: &Config,
    billets: &[String],
) -> Result<(), CliError> {
    // 1. Build claims: iss=issuer, sub="bootstrap:admin", aud=issuer, exp=now+600
    let claims = build_bootstrap_claims(config, billets);
    // 2. Sign JWT using KeyManager
    let token = sign_jwt(key_manager, &claims)?;
    // 3. Print raw JWT to stdout (no newline prefix, no formatting)
    print!("{}", token);
    Ok(())
}
