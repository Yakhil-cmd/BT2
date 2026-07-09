# Q277: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing` so each local sub-check inside `do_sign_participant` accepts its own `do_sign_participant` fragment, but the combined global statement over `do_sign_participant` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::do_sign_participant`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Make each local check over `do_sign_participant` pass independently, then verify whether the combined global statement over `do_sign_participant` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `do_sign_participant` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `do_sign_participant` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
