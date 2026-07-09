# Q2018: Break linearized aggregation

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `secret`, `old_reshare_package`, `protocol message timing` so `assert_keyshare_inputs` aggregates linearized `proof of knowledge` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_keyshare_inputs`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `proof of knowledge` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `proof of knowledge` and `received share`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `assert_keyshare_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
