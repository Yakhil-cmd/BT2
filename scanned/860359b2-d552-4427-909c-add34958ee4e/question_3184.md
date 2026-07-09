# Q3184: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `deserializer`, `protocol message timing` so repeated calls to `deserialize` expose share-dependent structure in `app_pk` or `app_id` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `deserializer`, `protocol message timing`
- Exploit idea: Query `app_pk` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `app_pk` or `app_id`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `deserialize`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
