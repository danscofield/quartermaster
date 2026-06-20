# Requirements Document — Bootstrap CLI (`qm-bootstrap`)

## Introduction

A CLI binary (`qm-bootstrap`) that shares the Quartermaster config and DataStore code, enabling operators to seed billets, policies, and admin tokens directly into the backing store without a running server or existing credentials. Used for initial deployment bootstrap and operational debugging.

## Glossary

- **qm-bootstrap**: A separate binary in the same Cargo workspace that reads `QM_CONFIG_PATH` and operates directly on the DataStore.

## Requirements

### Requirement 1: Config Reuse

**User Story:** As an operator, I want the bootstrap CLI to read the same config file as the server, so that it connects to the same DataStore without duplicate configuration.

#### Acceptance Criteria

1. THE CLI SHALL load configuration via `QM_CONFIG_PATH` (same as the server)
2. THE CLI SHALL use the same `DataStore` factory to connect to whichever backend is configured (local, DynamoDB, Firestore)
3. THE CLI SHALL use the same `KeyManager` factory for token signing

### Requirement 2: Subcommands

**User Story:** As an operator, I want clear subcommands for common bootstrap operations.

#### Acceptance Criteria

1. THE CLI SHALL support the following subcommands:
   - `add-policy <billet> <file.cedar | ->` — create a policy from a file or stdin
   - `list-billets` — list all billets with name and description
   - `list-policies <billet>` — list policies for a billet (id + first line of statement)
   - `issue-token <billet1> [billet2...]` — issue a short-lived admin JWT containing the specified billets
2. IF no subcommand is provided or an unknown subcommand is given, THE CLI SHALL print usage and exit with code 1

### Requirement 3: Add Policy

**User Story:** As an operator, I want to seed Cedar policies into the DataStore before the server starts accepting requests, so that the admin authorization model is in place from first boot.

#### Acceptance Criteria

1. THE `add-policy` subcommand SHALL parse the Cedar statement and reject invalid syntax with a descriptive error (exit code 1)
2. THE `add-policy` subcommand SHALL verify the target billet exists in the DataStore before writing (exit code 1 if not found)
3. THE `add-policy` subcommand SHALL generate a UUID for the policy ID, write the policy record, and print the policy ID on success
4. WHEN the source is `-`, THE CLI SHALL read the Cedar statement from stdin
5. THE `add-policy` subcommand SHALL NOT perform resource scope validation — this is an escape hatch for bootstrapping system billet policies (which are exempt from scope validation at the API layer)

### Requirement 4: Issue Token

**User Story:** As an operator, I want to issue a one-time admin JWT for initial API access, so that I can call the admin API to set up the system.

#### Acceptance Criteria

1. THE `issue-token` subcommand SHALL sign a JWT using the configured KeyManager with the specified billets in the `billets` claim
2. THE issued token SHALL have: `iss` = configured issuer, `sub` = `"bootstrap:admin"`, `aud` = configured issuer, `exp` = 10 minutes from now
3. THE CLI SHALL print only the raw JWT to stdout (no extra formatting), enabling piping: `TOKEN=$(qm-bootstrap issue-token quartermaster-admin)`
4. IF the signing key cannot be loaded, THE CLI SHALL exit with code 1 and a descriptive error

### Requirement 5: List Operations

**User Story:** As an operator, I want to inspect what's in the DataStore to verify bootstrap completed correctly.

#### Acceptance Criteria

1. `list-billets` SHALL print one line per billet: `<name> — <description>`
2. `list-policies <billet>` SHALL print one line per policy: `[<policy_id>] <first line of statement>`
3. IF no items exist, print a "none found" message (not an error)

### Requirement 6: Binary Structure

**User Story:** As a developer, I want the bootstrap CLI to be a separate binary in the same crate.

#### Acceptance Criteria

1. THE CLI SHALL be defined as `[[bin]] name = "qm-bootstrap"` in `Cargo.toml`
2. THE CLI source SHALL live at `src/bin/qm_bootstrap.rs`
3. THE CLI SHALL reuse library code from the `quartermaster` crate (config, datastore, keymanager modules) — no duplication
4. THE CLI SHALL use `clap` or simple arg parsing (no heavy framework required for 4 subcommands)
