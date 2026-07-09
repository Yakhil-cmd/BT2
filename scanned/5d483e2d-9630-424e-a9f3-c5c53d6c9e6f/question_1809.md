# Q1809: Reuse helper output under new signer set

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and carry a previously valid `coordinator-selected signer set` helper output into a different participant set or threshold context where `fut_wrapper` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::fut_wrapper`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `coordinator-selected signer set` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
