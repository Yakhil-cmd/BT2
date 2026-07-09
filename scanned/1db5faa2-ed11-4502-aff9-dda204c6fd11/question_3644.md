# Q3644: Iterate toward hidden state

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and make repeated attacker-chosen queries around `root_shared` so the returned `message header` or `child channel` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/internal.rs::root_shared`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `channel tag`, `waitpoint`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `message header` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `message header` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message header` data into `root_shared`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
