# Q2860: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `v`, `protocol message timing` so each local sub-check inside `and_vec_mut` accepts its own `vec` fragment, but the combined global statement over `and` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::and_vec_mut`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `v`, `protocol message timing`
- Exploit idea: Make each local check over `vec` pass independently, then verify whether the combined global statement over `and` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `vec` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `vec` data into `and_vec_mut`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
