# Q167: Break linearized aggregation

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing` so `verify_proof_of_knowledge` aggregates linearized `coefficient commitment` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `coefficient commitment` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `coefficient commitment` and `public key commitments`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coefficient commitment` data into `verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
