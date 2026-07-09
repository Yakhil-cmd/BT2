# Q1076: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `participants`, `presignature`, `msg_hash`, `protocol message timing` so `compute_signature_share` reuses a transcript, hash, or domain-separation space for both `sigma share` and `OT transcript`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `sigma share` and `OT transcript` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `sigma share` namespace from every `OT transcript` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
