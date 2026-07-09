# Q3133: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` so repeated calls to `fut_wrapper_v1` expose share-dependent structure in `nonce commitment` or `nonce commitment` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/eddsa/sign.rs::fut_wrapper_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Query `nonce commitment` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `nonce commitment` or `nonce commitment`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `fut_wrapper_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
