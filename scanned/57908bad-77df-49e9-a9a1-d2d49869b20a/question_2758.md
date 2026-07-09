# Q2758: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `tag`, `val`, `protocol message timing` so repeated calls to `encode_with_tag` expose share-dependent structure in `waitpoint` or `message buffer` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/internal.rs::encode_with_tag`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `tag`, `val`, `protocol message timing`
- Exploit idea: Query `waitpoint` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `waitpoint` or `message buffer`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `encode_with_tag`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
