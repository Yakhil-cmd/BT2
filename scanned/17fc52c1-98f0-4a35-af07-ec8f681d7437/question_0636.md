# Q636: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing` so each local sub-check inside `do_ckd_coordinator` accepts its own `scalar wrapper` fragment, but the combined global statement over `encrypted CKD output` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_coordinator`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Make each local check over `scalar wrapper` pass independently, then verify whether the combined global statement over `encrypted CKD output` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `scalar wrapper` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `scalar wrapper` data into `do_ckd_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
