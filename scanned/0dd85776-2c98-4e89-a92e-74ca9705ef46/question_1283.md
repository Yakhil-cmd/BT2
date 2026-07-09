# Q1283: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `params`, `k0`, `k1`, `x`, `protocol message timing` so repeated calls to `correlated_ot_receiver` expose share-dependent structure in `alpha share` or `MTA package` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs::correlated_ot_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `k0`, `k1`, `x`, `protocol message timing`
- Exploit idea: Query `alpha share` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `alpha share` or `MTA package`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `alpha share` data into `correlated_ot_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
