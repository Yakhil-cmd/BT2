# Q1280: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `params`, `k0`, `k1`, `x`, `protocol message timing` so `correlated_ot_receiver` reuses a transcript, hash, or domain-separation space for both `big_r` and `Beaver triple`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs::correlated_ot_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `k0`, `k1`, `x`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `big_r` and `Beaver triple` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `big_r` namespace from every `Beaver triple` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `correlated_ot_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
