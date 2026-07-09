# Q443: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and pair a valid-looking `participant identifier` with a different `commitments_map` reveal so `do_sign_coordinator_v2` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_coordinator_v2`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Commit to one `participant identifier` and reveal another `commitments_map` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `participant identifier` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `do_sign_coordinator_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
