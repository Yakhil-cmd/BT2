# Q3441: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and craft `okm`, `Self`, `protocol message timing` so each local sub-check inside `from_okm` accepts its own `app_pk` fragment, but the combined global statement over `scalar wrapper` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_okm`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `okm`, `Self`, `protocol message timing`
- Exploit idea: Make each local check over `app_pk` pass independently, then verify whether the combined global statement over `scalar wrapper` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `app_pk` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `from_okm`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
