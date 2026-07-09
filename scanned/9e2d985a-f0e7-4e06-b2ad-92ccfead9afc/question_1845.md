# Q1845: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and choose `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so repeated calls to `sign` expose share-dependent structure in `presignature context` or `nonce commitment` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Query `presignature context` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `presignature context` or `nonce commitment`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
