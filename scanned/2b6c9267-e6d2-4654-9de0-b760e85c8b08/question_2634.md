# Q2634: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `secret_coefficients`, `protocol message timing` so each local sub-check inside `generate_coefficient_commitment` accepts its own `commitment hash` fragment, but the combined global statement over `domain_separator` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::generate_coefficient_commitment`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret_coefficients`, `protocol message timing`
- Exploit idea: Make each local check over `commitment hash` pass independently, then verify whether the combined global statement over `domain_separator` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `commitment hash` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `generate_coefficient_commitment`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
