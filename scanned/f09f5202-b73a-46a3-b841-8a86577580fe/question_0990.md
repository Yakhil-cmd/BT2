# Q990: Break linearized aggregation

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `header`, `to`, `data`, `protocol message timing` so `send_private` aggregates linearized `round message` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::send_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `to`, `data`, `protocol message timing`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `round message` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `round message` and `message header`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `round message` data into `send_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
