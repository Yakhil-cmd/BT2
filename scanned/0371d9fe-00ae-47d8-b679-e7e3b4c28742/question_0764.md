# Q764: Iterate toward hidden state

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and make repeated attacker-chosen queries around `validate_received_share` so the returned `session_id` or `public key commitments` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::validate_received_share`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitment`, `from`, `signing_share_from`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `session_id` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `session_id` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `validate_received_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
