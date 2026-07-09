# Q1916: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so each local sub-check inside `run_ckd_protocol` accepts its own `derived key output` fragment, but the combined global statement over `app_id` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Make each local check over `derived key output` pass independently, then verify whether the combined global statement over `app_id` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `derived key output` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `derived key output` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
