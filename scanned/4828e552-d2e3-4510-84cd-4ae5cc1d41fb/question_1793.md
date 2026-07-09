# Q1793: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `threshold`, `keygen_output`, `protocol message timing` so repeated calls to `construct_key_package` expose share-dependent structure in `construct` or `presignature context` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/redjubjub/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Query `construct` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `construct` or `presignature context`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `construct` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
