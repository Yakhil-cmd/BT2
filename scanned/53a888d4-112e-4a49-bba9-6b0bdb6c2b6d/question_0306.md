# Q306: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `participants`, `threshold`, `protocol message timing` so `do_generation` reuses a transcript, hash, or domain-separation space for both `Beaver triple` and `MTA package`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::do_generation`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `Beaver triple` and `MTA package` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `Beaver triple` namespace from every `MTA package` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `do_generation`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
