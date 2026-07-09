# Q1403: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `tv`, `protocol message timing` so each local sub-check inside `mta_receiver` accepts its own `OT transcript` fragment, but the combined global statement over `mta` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/mta.rs::mta_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `tv`, `protocol message timing`
- Exploit idea: Make each local check over `OT transcript` pass independently, then verify whether the combined global statement over `mta` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `OT transcript` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `mta_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
