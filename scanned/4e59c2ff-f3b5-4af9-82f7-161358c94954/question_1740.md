# Q1740: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` with attacker-chosen `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` and make `sign_v2` accept a zero or identity-valued `commitments_map` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `commitments_map` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `commitments_map` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
