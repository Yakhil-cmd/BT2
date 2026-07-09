# Q3118: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` with attacker-chosen `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` and make `fut_wrapper_v1` accept a zero or identity-valued `participant identifier` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::fut_wrapper_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `participant identifier` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `participant identifier` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `fut_wrapper_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
