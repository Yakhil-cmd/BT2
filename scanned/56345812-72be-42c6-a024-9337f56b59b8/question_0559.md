# Q559: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and craft `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing` so each local sub-check inside `do_sign_coordinator` accepts its own `commitments_map` fragment, but the combined global statement over `participant identifier` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/redjubjub/sign.rs::do_sign_coordinator`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Make each local check over `commitments_map` pass independently, then verify whether the combined global statement over `participant identifier` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `commitments_map` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
