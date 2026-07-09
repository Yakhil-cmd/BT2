# Q848: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `participants`, `waitpoint`, `protocol message timing` so repeated calls to `recv_from_others` expose share-dependent structure in `waitpoint` or `private channel` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/helpers.rs::recv_from_others`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `waitpoint`, `protocol message timing`
- Exploit idea: Query `waitpoint` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `waitpoint` or `private channel`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `recv_from_others`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
