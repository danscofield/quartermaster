# Implementation Plan: SPIFFE ID Path Pattern Extraction

## Overview

Replace the SPIRE Server API dependency with a configuration-driven regex pattern matching system. The implementation adds `PathPatternMatcher` for extracting workload attributes from SPIFFE ID paths, builds Cedar entities directly from captures (bypassing the legacy `WorkloadEntity` struct), and wires mode selection into startup configuration. The existing SPIRE API path remains for legacy deployments.

## Tasks

- [x] 1. Add `PathPatternConfig` to configuration and extend `SpireSourceConfig`
  - [x] 1.1 Add `PathPatternConfig` struct and extend `SpireSourceConfig` in `src/config/identity.rs`
    - Add `#[derive(Debug, Clone, Deserialize)] pub struct PathPatternConfig { pub pattern: String }` 
    - Add `#[serde(default)] pub path_patterns: Vec<PathPatternConfig>` field to `SpireSourceConfig`
    - _Requirements: 1.1_

  - [ ]* 1.2 Write unit tests for `PathPatternConfig` deserialization
    - Test TOML with `[[identity.spire.path_patterns]]` entries deserializes correctly
    - Test TOML without `path_patterns` defaults to empty vec
    - Test multiple pattern entries preserve order
    - _Requirements: 1.1, 1.2_

- [x] 2. Implement `PathPatternMatcher` core module
  - [x] 2.1 Create `src/domain/identity/path_pattern.rs` with `PathPatternMatcher` struct
    - Define `PathPatternMatcher`, `CompiledPattern`, and `PathPatternError` types
    - Implement `PathPatternMatcher::compile()` that compiles regex patterns, validates capture group names against `^[a-zA-Z_][a-zA-Z0-9_]*$`, and collects errors
    - Implement `PathPatternMatcher::extract()` that strips `spiffe://<trust_domain>` prefix and applies first-match-wins logic
    - Implement `PathPatternMatcher::warnings()` for patterns with zero named captures
    - Add `pub mod path_pattern;` to `src/domain/identity/mod.rs`
    - _Requirements: 1.2, 1.3, 1.4, 5.1, 5.2, 5.3_

  - [ ]* 2.2 Write property test for first-match-wins ordering
    - **Property 2: First-match-wins ordering**
    - Generate 2-3 overlapping patterns and a path that matches multiple; verify first match's captures are returned
    - **Validates: Requirements 1.2**

  - [ ]* 2.3 Write property test for capture groups becoming entity attributes
    - **Property 3: Capture groups become entity attributes**
    - Generate regex with N named groups and a matching path; verify exactly N captured attributes are produced
    - **Validates: Requirements 1.3, 2.3**

  - [ ]* 2.4 Write property test for no-match producing minimal result
    - **Property 4: No-match produces minimal entity**
    - Generate patterns and a path guaranteed not to match; verify empty captures
    - **Validates: Requirements 1.4**

  - [ ]* 2.5 Write property test for pattern validation rejecting invalid patterns
    - **Property 7: Pattern validation rejects invalid patterns**
    - Generate invalid regex strings and capture names with hyphens/digit-prefix; verify compile returns errors
    - **Validates: Requirements 5.1, 5.3**

  - [ ]* 2.6 Write unit tests for `PathPatternMatcher`
    - Test `compile` with valid patterns produces correct compiled patterns count
    - Test `compile` with invalid regex returns `InvalidRegex` error
    - Test `compile` with invalid capture names (hyphens, digits-first) returns `InvalidCaptureName` error
    - Test `compile` with no-capture pattern succeeds but `warnings()` returns `NoCaptures`
    - Test `extract` with matching first pattern returns correct captures
    - Test `extract` with second pattern match (first doesn't match) returns captures from second
    - Test `extract` with no matching patterns returns empty map
    - Test `extract` with SPIFFE ID from different trust domain returns empty map
    - _Requirements: 1.2, 1.3, 1.4, 5.1, 5.2, 5.3_

- [x] 3. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement direct Cedar entity construction from captures
  - [x] 4.1 Add `build_workload_entities_from_captures()` function in `src/cedar/mod.rs`
    - Build Cedar `Entity` with type `Quartermaster::Workload` directly from `(spiffe_id, trust_domain, HashMap<String, String>)`
    - Always set `spiffe_id` and `trust_domain` attributes
    - Add all captured key-value pairs as `String` attributes
    - No parent hierarchy — flat `Workload` entity
    - Empty selectors set
    - _Requirements: 2.1, 2.2, 2.3, 2.5_

  - [ ]* 4.2 Write property test for entity type always being Workload
    - **Property 5: Entity type is always Workload in path-pattern mode**
    - Generate arbitrary SPIFFE IDs and capture maps; verify entity type is always `Quartermaster::Workload`
    - **Validates: Requirements 2.1**

  - [ ]* 4.3 Write property test for selectors always being empty
    - **Property 6: Selectors are always empty in path-pattern mode**
    - Generate entities through the path-pattern construction path; verify selectors field is empty set
    - **Validates: Requirements 2.5**

  - [ ]* 4.4 Write unit tests for Cedar entity construction from captures
    - Test that built entity has type `Workload`
    - Test that `spiffe_id` and `trust_domain` attributes are always present
    - Test that captured attributes appear on the entity
    - Test that empty captures produce entity with only `spiffe_id` + `trust_domain`
    - _Requirements: 2.1, 2.2, 2.3, 2.5_

- [ ] 5. Implement mode selection and `NoOpSelectorEnricher`
  - [x] 5.1 Add `SelectorEnricher` trait and `NoOpSelectorEnricher` implementation
    - Define async trait `SelectorEnricher` with `get_selectors(&self, spiffe_id: &str) -> Vec<String>`
    - Implement `NoOpSelectorEnricher` that always returns empty vec
    - Place in appropriate module (e.g., `src/domain/identity/` or alongside existing enricher code)
    - _Requirements: 3.3, 4.2_

  - [x] 5.2 Implement startup mode selection logic based on config
    - When `path_patterns` is non-empty: create `PathPatternMatcher`, skip SPIRE API client creation
    - When `path_patterns` is empty + `server_addr` present: use existing `SpireSelectorEnricher` (legacy mode)
    - When `path_patterns` is empty + `server_addr` absent: use `NoOpSelectorEnricher`
    - Log info when `server_addr` is ignored due to `path_patterns` being present
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3_

  - [ ]* 5.3 Write unit tests for mode selection logic
    - Test: path_patterns present → PathPatternMatcher created, no API client
    - Test: no path_patterns + server_addr → SpireSelectorEnricher
    - Test: no path_patterns + no server_addr → NoOpSelectorEnricher
    - Test: path_patterns present + server_addr present → path_patterns wins, warning logged
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3_

- [x] 6. Implement startup validation for path patterns
  - [x] 6.1 Add `validate_path_patterns()` method to `SpireSourceConfig`
    - Call `PathPatternMatcher::compile()` during startup validation
    - Propagate fatal errors (invalid regex, invalid capture names) to prevent server startup
    - Log warnings for patterns with zero named captures
    - _Requirements: 5.1, 5.2, 5.3_

  - [ ]* 6.2 Write property test for config deserialization round-trip
    - **Property 1: Config deserialization round-trip**
    - Generate valid TOML configurations with arbitrary pattern strings; verify deserialization preserves count and content
    - **Validates: Requirements 1.1**

  - [ ]* 6.3 Write unit tests for startup validation
    - Test fatal error on invalid regex prevents startup
    - Test fatal error on invalid capture group name prevents startup
    - Test warning logged for patterns with no named captures (startup succeeds)
    - Test valid patterns compile successfully
    - _Requirements: 5.1, 5.2, 5.3_

- [x] 7. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Wire path-pattern extraction into the token exchange hot path
  - [x] 8.1 Integrate `PathPatternMatcher` into the SPIRE identity authentication flow
    - After JWT-SVID/mTLS validation extracts SPIFFE ID, check if path-pattern mode is active
    - If active: call `PathPatternMatcher::extract()` → `build_workload_entities_from_captures()`
    - If not active: continue with existing `EntityBuilder` flow (legacy path unchanged)
    - Ensure `SpireIdentity` struct and downstream handlers can route to the correct entity-building path
    - _Requirements: 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.5, 3.1_

  - [ ]* 8.2 Write integration tests for end-to-end path pattern extraction
    - Test: configure path patterns, submit JWT-SVID with matching SPIFFE ID, verify Cedar evaluation uses captured attributes
    - Test: submit SPIFFE ID that matches no pattern, verify authorization uses minimal entity (only spiffe_id + trust_domain)
    - Test: configure without path patterns + server_addr, verify SPIRE API enricher is invoked
    - _Requirements: 1.2, 1.3, 1.4, 2.1, 3.1, 4.1_

- [ ] 9. Update example configuration
  - [x] 9.1 Update `example/config.toml` with path pattern examples
    - Add commented-out `[[identity.spire.path_patterns]]` entries showing usage
    - Add inline comments explaining first-match-wins ordering and capture group semantics
    - _Requirements: 1.1, 1.5_

- [x] 10. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document using the `proptest` crate (already in dev-dependencies)
- Unit tests validate specific examples and edge cases
- The implementation bypasses `WorkloadEntity` entirely for path-pattern mode — the two code paths (legacy API and path-pattern) are independent
