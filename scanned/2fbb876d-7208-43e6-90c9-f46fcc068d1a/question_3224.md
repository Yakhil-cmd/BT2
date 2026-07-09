# Q3224: Interpolate on malicious subset

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and steer `id`, `protocol message timing` so `try_new` interpolates `app_id` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::try_new`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `id`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `app_id` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `app_id`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `try_new`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
