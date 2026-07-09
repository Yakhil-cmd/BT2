# Q3606: Omit context from rerandomization

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `root_private` so `waitpoint` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::root_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `p0`, `p1`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `waitpoint` helper material.
- Invariant to test: Derived or rerandomized `waitpoint` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `root_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
