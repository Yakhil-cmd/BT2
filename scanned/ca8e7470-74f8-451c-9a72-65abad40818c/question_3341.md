# Q3341: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and make repeated attacker-chosen queries around `hash_to_curve` so the returned `hash_app_id_with_pk binding` or `app_pk` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_curve`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `hash_app_id_with_pk binding` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `hash_app_id_with_pk binding` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `hash_to_curve`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
