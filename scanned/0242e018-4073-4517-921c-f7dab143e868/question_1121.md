# Q1121: Reuse helper output under new signer set

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and carry a previously valid `OT transcript` helper output into a different participant set or threshold context where `sign` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `OT transcript` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
