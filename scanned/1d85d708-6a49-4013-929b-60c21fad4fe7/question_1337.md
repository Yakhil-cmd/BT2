# Q1337: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` with crafted `participants`, `threshold`, `protocol message timing` and exploit `generate_triple_many` so participant ordering or identifier mapping for `beta share` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `beta share` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `beta share` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
