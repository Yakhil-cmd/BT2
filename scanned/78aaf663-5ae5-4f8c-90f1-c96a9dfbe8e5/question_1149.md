# Q1149: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `delta`, `x`, `protocol message timing` so each local sub-check inside `batch_random_ot_receiver` accepts its own `ot` fragment, but the combined global statement over `bit-matrix expansion` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs::batch_random_ot_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `delta`, `x`, `protocol message timing`
- Exploit idea: Make each local check over `ot` pass independently, then verify whether the combined global statement over `bit-matrix expansion` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `ot` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `ot` data into `batch_random_ot_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
