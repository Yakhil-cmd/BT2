# Q24: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `participants`, `threshold`, `protocol message timing` and make `assert_key_invariants` accept a zero or identity-valued `received share` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_key_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `received share` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `received share` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `assert_key_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
