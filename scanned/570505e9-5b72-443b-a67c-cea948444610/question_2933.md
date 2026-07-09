# Q2933: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `bytes`, `protocol message timing` so repeated calls to `from_bytes` expose share-dependent structure in `Beaver triple` or `bytes` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::from_bytes`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Query `Beaver triple` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `Beaver triple` or `bytes`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `from_bytes`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
