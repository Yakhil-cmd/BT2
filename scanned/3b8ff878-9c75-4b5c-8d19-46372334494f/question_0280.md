# Q280: Alias two identities into one slot

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and craft `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_participant` treats two logical participants or sessions as the same `big_r` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::do_sign_participant`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Create two attacker-controlled representations that collide onto one `big_r` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
