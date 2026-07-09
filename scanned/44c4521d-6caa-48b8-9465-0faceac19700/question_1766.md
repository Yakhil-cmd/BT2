# Q1766: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` with attacker-chosen `participants`, `args`, `protocol message timing` and make `presign` accept a zero or identity-valued `signing nonces` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `signing nonces` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `signing nonces` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
