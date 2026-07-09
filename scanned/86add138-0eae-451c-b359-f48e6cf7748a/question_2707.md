# Q2707: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `n`, `protocol message timing` so repeated calls to `echo_ready_thresholds` expose share-dependent structure in `waitpoint` or `round message` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/echo_broadcast.rs::echo_ready_thresholds`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `n`, `protocol message timing`
- Exploit idea: Query `waitpoint` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `waitpoint` or `round message`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `echo_ready_thresholds`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
