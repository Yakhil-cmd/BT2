# Q1479: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `sid`, `a_i`, `b_i`, `precomputed_package`, `protocol message timing` so each local sub-check inside `multiplication_receiver` accepts its own `big_r` fragment, but the combined global statement over `beta share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/multiplication.rs::multiplication_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `sid`, `a_i`, `b_i`, `precomputed_package`, `protocol message timing`
- Exploit idea: Make each local check over `big_r` pass independently, then verify whether the combined global statement over `beta share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `big_r` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `multiplication_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
