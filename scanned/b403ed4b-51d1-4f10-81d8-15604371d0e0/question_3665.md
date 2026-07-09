# Q3665: Reuse helper output under new signer set

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `round message` helper output into a different participant set or threshold context where `shared_channel` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::shared_channel`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `shared channel`, `private channel`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `round message` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `round message` data into `shared_channel`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
