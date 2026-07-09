# Q3770: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `alpha share`, `beta share`, `protocol message timing` so each local sub-check inside `rows` accepts its own `beta share` fragment, but the combined global statement over `triple share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::rows`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `alpha share`, `beta share`, `protocol message timing`
- Exploit idea: Make each local check over `beta share` pass independently, then verify whether the combined global statement over `triple share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `beta share` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `beta share` data into `rows`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
