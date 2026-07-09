# Q3226: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and swap `new` for attacker-chosen `hash_app_id_with_pk binding` while keeping the rest of `id`, `protocol message timing` valid enough that `try_new` produces an accepted unauthorized output, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::try_new`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `id`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `new` outputs must be bound to the exact `hash_app_id_with_pk binding` selected by the honest protocol run.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new` data into `try_new`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
