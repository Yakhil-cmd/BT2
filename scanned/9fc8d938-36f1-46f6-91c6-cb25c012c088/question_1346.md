# Q1346: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and replay an old `Beaver triple` or cached `sigma share` into `generate_triple_many` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `Beaver triple` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
