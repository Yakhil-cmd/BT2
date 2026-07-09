# Q977: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `header`, `data`, `protocol message timing` so repeated calls to `send_many` expose share-dependent structure in `message buffer` or `channel tag` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/internal.rs::send_many`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `data`, `protocol message timing`
- Exploit idea: Query `message buffer` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `message buffer` or `channel tag`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message buffer` data into `send_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
