# Q251: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing` so each local sub-check inside `do_sign_coordinator` accepts its own `beta share` fragment, but the combined global statement over `sigma share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Make each local check over `beta share` pass independently, then verify whether the combined global statement over `sigma share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `beta share` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `beta share` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
