# Q643: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing` so repeated calls to `do_ckd_coordinator` expose share-dependent structure in `app_id` or `scalar wrapper` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_coordinator`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Query `app_id` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `app_id` or `scalar wrapper`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `do_ckd_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
