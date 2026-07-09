# Q281: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_participant` reuses a transcript, hash, or domain-separation space for both `triple share` and `do_sign_participant`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::do_sign_participant`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `triple share` and `do_sign_participant` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `triple share` namespace from every `do_sign_participant` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `triple share` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
