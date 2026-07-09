# Q2667: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing` and make `internal_verify_proof_of_knowledge` accept a zero or identity-valued `proof of knowledge` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::internal_verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `proof of knowledge` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `proof of knowledge` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `internal_verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
