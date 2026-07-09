# Q711: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `session_id`, `domain_separator`, `coefficients`, `coefficient_commitment`, `protocol message timing` so each local sub-check inside `proof_of_knowledge` accepts its own `of` fragment, but the combined global statement over `of` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `coefficients`, `coefficient_commitment`, `protocol message timing`
- Exploit idea: Make each local check over `of` pass independently, then verify whether the combined global statement over `of` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `of` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `of` data into `proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
