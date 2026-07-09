# Q147: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing` so each local sub-check inside `verify_commitment_hash` accepts its own `new participant set` fragment, but the combined global statement over `new participant set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::verify_commitment_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Make each local check over `new participant set` pass independently, then verify whether the combined global statement over `new participant set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `new participant set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `verify_commitment_hash`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
