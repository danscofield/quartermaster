# Implementation Plan: Bootstrap CLI (`qm-bootstrap`)

## Overview

Implement a separate binary (`qm-bootstrap`) in the existing Cargo workspace that provides four subcommands (`add-policy`, `list-billets`, `list-policies`, `issue-token`) for bootstrap and operational debugging. The binary reuses the `quartermaster` library crate's `config`, `datastore`, and `keymanager` modules directly, adding only CLI argument parsing (clap derive) and thin subcommand handlers.

## Tasks

- [x] 1. Set up binary target and CLI argument structure
  - [x] 1.1 Add `[[bin]]` entry for `qm-bootstrap` in `Cargo.toml` and add `clap` with `derive` feature to dependencies
    - Add `[[bin]] name = "qm-bootstrap" path = "src/bin/qm_bootstrap.rs"` to `Cargo.toml`
    - Add `clap = { version = "4", features = ["derive"] }` to `[dependencies]`
    - _Requirements: 6.1, 6.4_

  - [x] 1.2 Create `src/bin/qm_bootstrap.rs` with clap derive structs and main entrypoint
    - Define `Cli` struct with `#[derive(Parser)]` and `Commands` enum with `#[derive(Subcommand)]`
    - Implement `async fn main()` that parses args, loads config, builds DataStore, dispatches to subcommand handlers
    - Print errors to stderr, exit with code 1 on failure, code 0 on success
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 6.2, 6.3_

- [x] 2. Implement `add-policy` subcommand
  - [x] 2.1 Implement source reading (file path or stdin via `-`)
    - Create `read_source(source: &str) -> Result<String, CliError>` function
    - When `source == "-"`, read from stdin; otherwise read from file path
    - Return `IoError` on read failure
    - _Requirements: 3.4_

  - [x] 2.2 Implement Cedar syntax validation
    - Create `validate_cedar_syntax(statement: &str) -> Result<(), CliError>` function
    - Use `cedar_policy::PolicySet::from_str` to parse the Cedar statement
    - Return `CedarParseError` with descriptive message on invalid syntax
    - _Requirements: 3.1_

  - [x] 2.3 Implement billet existence check and policy write
    - Create `add_policy(data_store, billet, source) -> Result<(), CliError>` async handler
    - Call `data_store.get_billet(billet)` — return `BilletNotFound` error if `None`
    - Generate UUID v4 for policy ID, build `PolicyRecord`, call `data_store.create_policy`
    - Print policy ID to stdout on success
    - Do NOT perform resource scope validation (escape hatch for system billets)
    - _Requirements: 3.2, 3.3, 3.5_

  - [ ]* 2.4 Write property test: Cedar syntax validation rejects invalid input (Property 1)
    - **Property 1: Cedar syntax validation rejects invalid input**
    - Generate arbitrary strings via proptest; verify invalid Cedar is rejected and valid Cedar passes
    - **Validates: Requirements 3.1**

  - [ ]* 2.5 Write property test: Billet existence precondition (Property 2)
    - **Property 2: Billet existence precondition**
    - Generate random billet names; mock DataStore returning `None`; verify `add_policy` fails with BilletNotFound without writing
    - **Validates: Requirements 3.2**

  - [ ]* 2.6 Write property test: Policy ID is a valid UUID (Property 3)
    - **Property 3: Policy ID is a valid UUID**
    - Generate valid Cedar statements and mock an existing billet; capture written policy ID; verify it parses as UUID v4
    - **Validates: Requirements 3.3**

  - [ ]* 2.7 Write property test: No resource scope validation (Property 4)
    - **Property 4: No resource scope validation on bootstrap add-policy**
    - Generate valid Cedar policies with varying resource scopes (wildcards, other billet names); verify all are accepted
    - **Validates: Requirements 3.5**

- [x] 3. Implement `issue-token` subcommand
  - [x] 3.1 Implement JWT claim building and signing
    - Create `build_bootstrap_claims(config, billets) -> Claims` function
    - Set `iss` = config issuer, `sub` = `"bootstrap:admin"`, `aud` = config issuer, `billets` = input billets, `exp` = now + 600, `jti` = UUID v4
    - Create `issue_token(key_manager, config, billets) -> Result<(), CliError>` async handler
    - Sign JWT using `KeyManager::encoding_key()` and `KeyManager::header()`
    - Print raw JWT to stdout (no newline, no extra formatting) for piping
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ]* 3.2 Write property test: JWT claim round-trip correctness (Property 5)
    - **Property 5: JWT claim round-trip correctness**
    - Generate random issuer strings and billet name lists; issue token; decode claims; verify iss, sub, aud, billets, exp-iat==600
    - **Validates: Requirements 4.1, 4.2**

  - [ ]* 3.3 Write property test: JWT output is raw token format (Property 6)
    - **Property 6: JWT output is raw token format**
    - Generate random inputs; capture stdout output; verify it matches JWT regex `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`
    - **Validates: Requirements 4.3**

- [x] 4. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement list subcommands
  - [x] 5.1 Implement `list-billets` handler
    - Create `list_billets(data_store) -> Result<(), CliError>` async handler
    - Call `data_store.list_billets()`, print each as `<name> — <description>`
    - If empty, print `"no billets found"` (exit 0, not an error)
    - _Requirements: 5.1, 5.3_

  - [x] 5.2 Implement `list-policies` handler
    - Create `list_policies(data_store, billet) -> Result<(), CliError>` async handler
    - Call `data_store.list_policies_for_billet(billet)`, print each as `[<policy_id>] <first_line>`
    - If empty, print `"no policies found for '<billet>'"` (exit 0, not an error)
    - _Requirements: 5.2, 5.3_

  - [ ]* 5.3 Write property test: list-billets output format (Property 7)
    - **Property 7: list-billets output format**
    - Generate random lists of `BilletRecord` (N ≥ 1); format output; verify exactly N lines matching `<name> — <description>`
    - **Validates: Requirements 5.1**

  - [ ]* 5.4 Write property test: list-policies output format (Property 8)
    - **Property 8: list-policies output format**
    - Generate random lists of `PolicyRecord` (N ≥ 1); format output; verify exactly N lines matching `[<policy_id>] <first_line>`
    - **Validates: Requirements 5.2**

- [x] 6. Wire together and verify end-to-end
  - [x] 6.1 Complete main dispatch and error handling
    - Ensure all subcommands are wired in the `match` dispatch in `main()`
    - Map all `CliError` variants to stderr messages with exit code 1
    - Verify clap auto-generates usage/help on missing or unknown subcommand (exit code 1)
    - _Requirements: 2.2, 6.3_

  - [ ]* 6.2 Write integration tests
    - Test end-to-end: create temp local DataStore config, run `add-policy` with valid Cedar, verify `list-policies` shows it
    - Test `issue-token` produces a JWT decodable with the configured signing key
    - Test error paths: missing config, invalid Cedar, nonexistent billet
    - _Requirements: 1.1, 1.2, 2.1, 3.1, 3.2, 4.1_

- [x] 7. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- The CLI reuses existing `quartermaster` library code — no duplication of config, datastore, or keymanager logic
- Property tests use `proptest` (already in dev-dependencies) and `mockall` for DataStore mocking
- Checkpoints ensure incremental validation before moving to the next phase
