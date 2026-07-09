# Q646: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` with crafted `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` and exploit `do_ckd_participant` so participant ordering or identifier mapping for `hash_app_id_with_pk binding` differs across nodes, breaking signer-set consistency and leading to Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_participant`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `hash_app_id_with_pk binding` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `do_ckd_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
