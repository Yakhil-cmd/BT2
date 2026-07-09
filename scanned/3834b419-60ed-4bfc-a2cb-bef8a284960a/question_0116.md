# Q116: Break linearized aggregation

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing` so `do_reshare` aggregates linearized `reshare` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `reshare` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `reshare` and `session_id`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `reshare` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
