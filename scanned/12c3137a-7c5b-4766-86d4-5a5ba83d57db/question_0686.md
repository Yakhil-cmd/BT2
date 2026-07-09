# Q686: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing` so each local sub-check inside `challenge` accepts its own `proof of knowledge` fragment, but the combined global statement over `session_id` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing`
- Exploit idea: Make each local check over `proof of knowledge` pass independently, then verify whether the combined global statement over `session_id` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `proof of knowledge` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `challenge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
