# Q1758: Reuse helper output under new signer set

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and carry a previously valid `participant identifier` helper output into a different participant set or threshold context where `presign` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `participant identifier` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
