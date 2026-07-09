# Q2635: Iterate toward hidden state

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and make repeated attacker-chosen queries around `generate_coefficient_commitment` so the returned `new participant set` or `coefficient` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::generate_coefficient_commitment`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret_coefficients`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `new participant set` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `new participant set` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `generate_coefficient_commitment`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
