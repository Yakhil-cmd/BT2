# Q706: Break linearized aggregation

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `session_id`, `domain_separator`, `coefficients`, `coefficient_commitment`, `protocol message timing` so `proof_of_knowledge` aggregates linearized `old participant set` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `coefficients`, `coefficient_commitment`, `protocol message timing`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `old participant set` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `old participant set` and `of`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
