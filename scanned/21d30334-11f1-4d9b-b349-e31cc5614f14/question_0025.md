# Q25: Exploit non-canonical decoding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use multiple encodings of `proof of knowledge` so `assert_key_invariants` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_key_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `proof of knowledge` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `proof of knowledge` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `assert_key_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
