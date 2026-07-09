# Q2935: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `bytes`, `protocol message timing` so each local sub-check inside `from_bytes` accepts its own `OT transcript` fragment, but the combined global statement over `OT transcript` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::from_bytes`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Make each local check over `OT transcript` pass independently, then verify whether the combined global statement over `OT transcript` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `OT transcript` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `from_bytes`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
