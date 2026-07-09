# Q2686: Validate same bytes under two meanings

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and submit the same raw `old participant set` bytes under two semantic interpretations so `internal_verify_proof_of_knowledge` accepts both paths even though only one should be valid, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::internal_verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Submit identical raw bytes for `old participant set` under two semantic interpretations and test whether both verification paths accept them.
- Invariant to test: The same `old participant set` bytes must not validate under multiple semantic domains, roles, or curve/group interpretations.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `internal_verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
