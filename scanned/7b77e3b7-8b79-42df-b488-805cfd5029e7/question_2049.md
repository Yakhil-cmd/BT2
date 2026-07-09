# Q2049: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and craft `participants`, `coordinator`, `threshold`, `protocol message timing` so each local sub-check inside `assert_sign_inputs` accepts its own `coordinator-selected signer set` fragment, but the combined global statement over `coordinator-selected signer set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `coordinator-selected signer set` pass independently, then verify whether the combined global statement over `coordinator-selected signer set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `coordinator-selected signer set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
