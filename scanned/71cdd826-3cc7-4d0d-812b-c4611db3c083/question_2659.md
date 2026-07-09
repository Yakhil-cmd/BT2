# Q2659: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `threshold`, `commitment_i`, `protocol message timing` so each local sub-check inside `insert_identity_if_missing` accepts its own `public key commitments` fragment, but the combined global statement over `old participant set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::insert_identity_if_missing`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `threshold`, `commitment_i`, `protocol message timing`
- Exploit idea: Make each local check over `public key commitments` pass independently, then verify whether the combined global statement over `old participant set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `public key commitments` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `public key commitments` data into `insert_identity_if_missing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
