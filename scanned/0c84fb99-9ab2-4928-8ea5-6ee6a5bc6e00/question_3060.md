# Q3060: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `i`, `v`, `protocol message timing` so each local sub-check inside `hash_to_scalar` accepts its own `bit-matrix expansion` fragment, but the combined global statement over `OT transcript` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/random_ot_extension.rs::hash_to_scalar`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `i`, `v`, `protocol message timing`
- Exploit idea: Make each local check over `bit-matrix expansion` pass independently, then verify whether the combined global statement over `OT transcript` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `bit-matrix expansion` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `hash_to_scalar`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
