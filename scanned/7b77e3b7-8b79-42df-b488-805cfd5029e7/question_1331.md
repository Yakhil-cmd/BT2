# Q1331: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and choose `participants`, `threshold`, `protocol message timing` so `generate_triple` reuses a transcript, hash, or domain-separation space for both `MTA package` and `big_r`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `MTA package` and `big_r` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `MTA package` namespace from every `big_r` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `MTA package` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
