# Q1683: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and craft `threshold`, `signing_share`, `verifying_key`, `protocol message timing` so each local sub-check inside `construct_key_package` accepts its own `presignature context` fragment, but the combined global statement over `key package` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Make each local check over `presignature context` pass independently, then verify whether the combined global statement over `key package` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `presignature context` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
