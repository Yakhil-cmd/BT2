# Q2618: Exploit non-canonical decoding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use multiple encodings of `domain_separator` so `generate_coefficient_commitment` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::generate_coefficient_commitment`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret_coefficients`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `domain_separator` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `domain_separator` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `generate_coefficient_commitment`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
