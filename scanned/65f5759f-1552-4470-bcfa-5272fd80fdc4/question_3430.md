# Q3430: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and swap `app_id` for attacker-chosen `hash_app_id_with_pk binding` while keeping the rest of `okm`, `Self`, `protocol message timing` valid enough that `from_okm` produces an accepted unauthorized output, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_okm`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `okm`, `Self`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `app_id` outputs must be bound to the exact `hash_app_id_with_pk binding` selected by the honest protocol run.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `from_okm`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
