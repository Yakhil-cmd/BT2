# Q3389: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `scalar`, `Self`, `protocol message timing` so repeated calls to `invert` expose share-dependent structure in `derived key output` or `hash_app_id_with_pk binding` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::invert`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `scalar`, `Self`, `protocol message timing`
- Exploit idea: Query `derived key output` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `derived key output` or `hash_app_id_with_pk binding`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `derived key output` data into `invert`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
