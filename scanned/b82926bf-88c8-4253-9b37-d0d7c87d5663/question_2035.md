# Q2035: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and pair a valid-looking `coordinator-selected signer set` with a different `signing nonces` reveal so `assert_sign_inputs` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Commit to one `coordinator-selected signer set` and reveal another `signing nonces` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `coordinator-selected signer set` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
