# Q2983: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `other`, `protocol message timing` so repeated calls to `gf_mul` expose share-dependent structure in `sigma share` or `sigma share` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::gf_mul`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `other`, `protocol message timing`
- Exploit idea: Query `sigma share` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `sigma share` or `sigma share`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `gf_mul`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
