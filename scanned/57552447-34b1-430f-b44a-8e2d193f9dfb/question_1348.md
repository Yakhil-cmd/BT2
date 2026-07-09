# Q1348: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and use crafted batching inputs in `participants`, `threshold`, `protocol message timing` so `generate_triple_many` remaps one party's `big_r` to another party's `generate_triple_many` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `big_r` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`big_r` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
