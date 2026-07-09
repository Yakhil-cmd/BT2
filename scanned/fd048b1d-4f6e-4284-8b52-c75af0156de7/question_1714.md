# Q1714: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` with attacker-chosen `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` and make `sign_v1` accept a zero or identity-valued `coordinator-selected signer set` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `coordinator-selected signer set` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `coordinator-selected signer set` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
