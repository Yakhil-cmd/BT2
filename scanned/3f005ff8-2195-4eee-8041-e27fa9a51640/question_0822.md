# Q822: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `participants`, `wait`, `data`, `protocol message timing` so repeated calls to `reliable_broadcast_send` expose share-dependent structure in `send` or `shared channel` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/echo_broadcast.rs::reliable_broadcast_send`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `wait`, `data`, `protocol message timing`
- Exploit idea: Query `send` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `send` or `shared channel`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `send` data into `reliable_broadcast_send`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
