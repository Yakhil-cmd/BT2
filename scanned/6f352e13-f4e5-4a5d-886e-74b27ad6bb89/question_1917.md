# Q1917: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and make repeated attacker-chosen queries around `run_ckd_protocol` so the returned `run` or `derived key output` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `run` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `run` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `run` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
