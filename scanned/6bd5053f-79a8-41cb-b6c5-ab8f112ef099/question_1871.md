# Q1871: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::protocol::ckd(...)` and choose `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so repeated calls to `ckd` expose share-dependent structure in `hash_app_id_with_pk binding` or `big_c` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::ckd`
- Entrypoint: `confidential_key_derivation::protocol::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Query `hash_app_id_with_pk binding` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `hash_app_id_with_pk binding` or `big_c`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::protocol::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `ckd`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
