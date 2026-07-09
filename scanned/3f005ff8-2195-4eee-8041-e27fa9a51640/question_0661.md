# Q661: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so each local sub-check inside `do_ckd_participant` accepts its own `big_c` fragment, but the combined global statement over `big_c` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_participant`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Make each local check over `big_c` pass independently, then verify whether the combined global statement over `big_c` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `big_c` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_c` data into `do_ckd_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
