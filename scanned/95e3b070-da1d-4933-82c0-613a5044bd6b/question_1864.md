# Q1864: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::protocol::ckd(...)` and craft `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so each local sub-check inside `ckd` accepts its own `hash_app_id_with_pk binding` fragment, but the combined global statement over `encrypted CKD output` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::ckd`
- Entrypoint: `confidential_key_derivation::protocol::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Make each local check over `hash_app_id_with_pk binding` pass independently, then verify whether the combined global statement over `encrypted CKD output` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `hash_app_id_with_pk binding` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::protocol::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `ckd`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
