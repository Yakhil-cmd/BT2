# Q1333: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and use multiple encodings of `sigma share` so `generate_triple` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `sigma share` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `sigma share` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
