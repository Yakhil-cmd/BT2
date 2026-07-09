# Q1670: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and pair a valid-looking `coordinator-selected signer set` with a different `key package` reveal so `construct_key_package` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Commit to one `coordinator-selected signer set` and reveal another `key package` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `coordinator-selected signer set` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
