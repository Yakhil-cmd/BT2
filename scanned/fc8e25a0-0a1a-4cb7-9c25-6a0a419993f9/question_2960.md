# Q2960: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `rows`, `protocol message timing` so each local sub-check inside `from_rows` accepts its own `rows` fragment, but the combined global statement over `MTA package` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::from_rows`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `rows`, `protocol message timing`
- Exploit idea: Make each local check over `rows` pass independently, then verify whether the combined global statement over `MTA package` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `rows` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `rows` data into `from_rows`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
