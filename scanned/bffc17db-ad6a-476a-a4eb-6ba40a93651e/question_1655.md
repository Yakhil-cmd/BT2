# Q1655: Reuse helper output under new signer set

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::sign::sign(...)` and carry a previously valid `degree-2t share` helper output into a different participant set or threshold context where `sign` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::robust_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `max_malicious`, `public_key`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `degree-2t share` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `degree-2t share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
