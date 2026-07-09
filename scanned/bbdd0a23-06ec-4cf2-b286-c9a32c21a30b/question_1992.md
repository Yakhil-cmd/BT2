# Q1992: Break linearized aggregation

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and craft `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` aggregates linearized `public key` values under a different algebraic relation than the one honest parties believe they checked, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Bias the linearization inputs so honest nodes add valid-looking `public key` values under inconsistent assumptions.
- Invariant to test: Every node must apply the same algebraic relation when aggregating `public key` and `participant set`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `public key` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
