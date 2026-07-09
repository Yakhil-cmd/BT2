# Q1613: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and choose `participants`, `presignature`, `msg_hash`, `protocol message timing` so repeated calls to `compute_signature_share` expose share-dependent structure in `w share` or `degree-2t share` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Query `w share` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `w share` or `degree-2t share`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
