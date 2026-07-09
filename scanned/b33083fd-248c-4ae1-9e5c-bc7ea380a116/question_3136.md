# Q3136: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and craft `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` so each local sub-check inside `fut_wrapper_v1` accepts its own `nonce commitment` fragment, but the combined global statement over `v1` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::fut_wrapper_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Make each local check over `nonce commitment` pass independently, then verify whether the combined global statement over `v1` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `nonce commitment` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `fut_wrapper_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
