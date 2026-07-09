# Q3660: Reuse child-channel state

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `shared_channel` so concurrently running sessions reuse a child-channel or waitpoint namespace for `waitpoint`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::shared_channel`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `message buffer`, `round message`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `waitpoint` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `waitpoint`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `shared_channel`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
