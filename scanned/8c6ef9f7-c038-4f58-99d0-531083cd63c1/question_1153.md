# Q1153: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `delta`, `x`, `protocol message timing` so `batch_random_ot_receiver` reuses a transcript, hash, or domain-separation space for both `bit-matrix expansion` and `sigma share`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs::batch_random_ot_receiver`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `delta`, `x`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `bit-matrix expansion` and `sigma share` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `bit-matrix expansion` namespace from every `sigma share` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `batch_random_ot_receiver`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
