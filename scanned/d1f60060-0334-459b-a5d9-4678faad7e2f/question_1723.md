# Q1723: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and exploit `sign_v2` so `signing nonces` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `signing nonces` helper material.
- Invariant to test: Derived or rerandomized `signing nonces` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
