# Q2733: Leak sensitive state through output

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `i`, `protocol message timing` so repeated calls to `child` expose share-dependent structure in `child channel` or `round message` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/protocol/internal.rs::child`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `i`, `protocol message timing`
- Exploit idea: Query `child channel` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `child channel` or `round message`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `child channel` data into `child`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
