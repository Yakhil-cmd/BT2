# Q540: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `participants`, `signing_share`, `protocol message timing` so repeated calls to `do_presign` expose share-dependent structure in `nonce commitment` or `key package` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/mod.rs::do_presign`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `signing_share`, `protocol message timing`
- Exploit idea: Query `nonce commitment` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `nonce commitment` or `key package`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
