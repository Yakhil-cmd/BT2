# Q1749: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and exploit `presign` so `participant identifier` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `participant identifier` helper material.
- Invariant to test: Derived or rerandomized `participant identifier` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
