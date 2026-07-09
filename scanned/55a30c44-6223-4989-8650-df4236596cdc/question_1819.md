# Q1819: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so repeated calls to `fut_wrapper` expose share-dependent structure in `coordinator-selected signer set` or `presignature context` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/redjubjub/sign.rs::fut_wrapper`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Query `coordinator-selected signer set` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `coordinator-selected signer set` or `presignature context`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
