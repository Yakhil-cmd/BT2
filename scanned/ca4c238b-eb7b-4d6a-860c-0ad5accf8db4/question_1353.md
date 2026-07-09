# Q1353: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and craft `participants`, `threshold`, `protocol message timing` so each local sub-check inside `generate_triple_many` accepts its own `Beaver triple` fragment, but the combined global statement over `beta share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `Beaver triple` pass independently, then verify whether the combined global statement over `beta share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `Beaver triple` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
