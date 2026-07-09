# Q1301: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `params`, `delta`, `k`, `protocol message timing` so each local sub-check inside `correlated_ot_sender` accepts its own `correlated` fragment, but the combined global statement over `presignature` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs::correlated_ot_sender`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `delta`, `k`, `protocol message timing`
- Exploit idea: Make each local check over `correlated` pass independently, then verify whether the combined global statement over `presignature` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `correlated` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `correlated` data into `correlated_ot_sender`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
