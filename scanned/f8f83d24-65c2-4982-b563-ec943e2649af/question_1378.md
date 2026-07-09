# Q1378: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `participants`, `threshold`, `protocol message timing` so each local sub-check inside `validate_triple_inputs` accepts its own `Beaver triple` fragment, but the combined global statement over `alpha share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::validate_triple_inputs`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `Beaver triple` pass independently, then verify whether the combined global statement over `alpha share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `Beaver triple` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `validate_triple_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
