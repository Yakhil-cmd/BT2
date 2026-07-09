# Q1716: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and choose `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` so repeated calls to `sign_v1` expose share-dependent structure in `participant identifier` or `commitments_map` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Query `participant identifier` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `participant identifier` or `commitments_map`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
