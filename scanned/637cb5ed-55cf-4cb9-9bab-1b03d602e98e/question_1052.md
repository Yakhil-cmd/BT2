# Q1052: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign::presign(...)` with attacker-chosen `participants`, `args`, `protocol message timing` and make `presign` accept a zero or identity-valued `big_r` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `big_r` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `big_r` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
