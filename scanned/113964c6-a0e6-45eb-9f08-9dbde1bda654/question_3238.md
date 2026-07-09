# Q3238: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `id`, `protocol message timing` so each local sub-check inside `try_new` accepts its own `new` fragment, but the combined global statement over `app_id` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::try_new`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `id`, `protocol message timing`
- Exploit idea: Make each local check over `new` pass independently, then verify whether the combined global statement over `app_id` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `new` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new` data into `try_new`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
