# Q668: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so repeated calls to `do_ckd_participant` expose share-dependent structure in `ckd` or `hash_app_id_with_pk binding` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_participant`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Query `ckd` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `ckd` or `hash_app_id_with_pk binding`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `ckd` data into `do_ckd_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
