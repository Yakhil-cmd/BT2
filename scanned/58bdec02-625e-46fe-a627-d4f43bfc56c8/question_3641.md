# Q3641: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `private channel`, `child channel`, `protocol message timing` so repeated calls to `root_shared` expose share-dependent structure in `shared channel` or `message header` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/internal.rs::root_shared`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `private channel`, `child channel`, `protocol message timing`
- Exploit idea: Query `shared channel` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `shared channel` or `message header`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared channel` data into `root_shared`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
