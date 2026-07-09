# Q3213: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and make repeated attacker-chosen queries around `deserialize_reader` so the returned `big_c` or `derived key output` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize_reader`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `reader`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `big_c` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `big_c` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_c` data into `deserialize_reader`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
