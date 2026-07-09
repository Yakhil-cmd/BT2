# Q2643: Exploit non-canonical decoding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use multiple encodings of `domain_separator` so `insert_identity_if_missing` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::insert_identity_if_missing`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `threshold`, `commitment_i`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `domain_separator` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `domain_separator` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `insert_identity_if_missing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
