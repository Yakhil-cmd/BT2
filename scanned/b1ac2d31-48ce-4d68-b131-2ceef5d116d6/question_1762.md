# Q1762: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and make repeated attacker-chosen queries around `presign` so the returned `presignature context` or `key package` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `presignature context` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `presignature context` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
