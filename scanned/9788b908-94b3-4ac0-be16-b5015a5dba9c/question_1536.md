# Q1536: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `params`, `k0`, `k1`, `b`, `protocol message timing` so repeated calls to `random_ot_extension_receiver` expose share-dependent structure in `OT transcript` or `extension` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/random_ot_extension.rs::random_ot_extension_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `k0`, `k1`, `b`, `protocol message timing`
- Exploit idea: Query `OT transcript` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `OT transcript` or `extension`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `random_ot_extension_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
