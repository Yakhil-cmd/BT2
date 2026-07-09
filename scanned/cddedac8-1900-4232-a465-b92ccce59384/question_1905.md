# Q1905: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and swap `hash_app_id_with_pk binding` for attacker-chosen `app_pk` while keeping the rest of `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` valid enough that `run_ckd_protocol` produces an accepted unauthorized output, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `hash_app_id_with_pk binding` outputs must be bound to the exact `app_pk` selected by the honest protocol run.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
