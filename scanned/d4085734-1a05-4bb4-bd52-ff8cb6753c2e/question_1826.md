# Q1826: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and exploit `sign` so `signing nonces` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `signing nonces` helper material.
- Invariant to test: Derived or rerandomized `signing nonces` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
