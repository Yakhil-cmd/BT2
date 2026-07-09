# Q75: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `participants`, `threshold`, `protocol message timing` and make `do_keygen` accept a zero or identity-valued `domain_separator` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `domain_separator` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `domain_separator` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
