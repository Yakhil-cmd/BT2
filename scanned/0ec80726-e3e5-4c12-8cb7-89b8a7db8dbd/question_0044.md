# Q44: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing` so each local sub-check inside `assert_reshare_keys_invariants` accepts its own `old participant set` fragment, but the combined global statement over `coefficient commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_reshare_keys_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing`
- Exploit idea: Make each local check over `old participant set` pass independently, then verify whether the combined global statement over `coefficient commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `old participant set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `assert_reshare_keys_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
