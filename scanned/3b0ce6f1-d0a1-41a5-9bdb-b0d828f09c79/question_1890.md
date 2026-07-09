# Q1890: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing` so each local sub-check inside `compute_signature_share` accepts its own `signature` fragment, but the combined global statement over `scalar wrapper` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::compute_signature_share`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Make each local check over `signature` pass independently, then verify whether the combined global statement over `scalar wrapper` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `signature` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signature` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
