# Q2777: Reuse child-channel state

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `from_bytes` so concurrently running sessions reuse a child-channel or waitpoint namespace for `message header`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::from_bytes`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `message header` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `message header`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message header` data into `from_bytes`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
