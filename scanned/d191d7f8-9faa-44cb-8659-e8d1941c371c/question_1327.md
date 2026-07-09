# Q1327: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and craft `participants`, `threshold`, `protocol message timing` so each local sub-check inside `generate_triple` accepts its own `MTA package` fragment, but the combined global statement over `bit-matrix expansion` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `MTA package` pass independently, then verify whether the combined global statement over `bit-matrix expansion` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `MTA package` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `MTA package` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
