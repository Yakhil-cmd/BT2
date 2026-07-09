# Q3210: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `reader`, `protocol message timing` so repeated calls to `deserialize_reader` expose share-dependent structure in `reader` or `reader` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize_reader`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `reader`, `protocol message timing`
- Exploit idea: Query `reader` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `reader` or `reader`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `reader` data into `deserialize_reader`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
