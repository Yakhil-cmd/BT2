# Q1305: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `params`, `delta`, `k`, `protocol message timing` so `correlated_ot_sender` reuses a transcript, hash, or domain-separation space for both `presignature` and `correlated`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs::correlated_ot_sender`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `delta`, `k`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `presignature` and `correlated` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `presignature` namespace from every `correlated` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `correlated_ot_sender`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
