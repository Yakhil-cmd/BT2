# Q2992: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `participants`, `threshold`, `protocol message timing` so `create_transcript` reuses a transcript, hash, or domain-separation space for both `alpha share` and `OT transcript`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::create_transcript`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `alpha share` and `OT transcript` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `alpha share` namespace from every `OT transcript` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `alpha share` data into `create_transcript`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
