# Q302: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `participants`, `threshold`, `protocol message timing` so each local sub-check inside `do_generation` accepts its own `generation` fragment, but the combined global statement over `sigma share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::do_generation`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `generation` pass independently, then verify whether the combined global statement over `sigma share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `generation` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `generation` data into `do_generation`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
