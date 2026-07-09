# Q742: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `commitments`, `protocol message timing` and make `public_key_from_commitments` accept a zero or identity-valued `commitments` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `commitments` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `commitments` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
