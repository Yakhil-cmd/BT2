# Q3196: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and use multiple encodings of `derived key output` so `deserialize_reader` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize_reader`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `reader`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `derived key output` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `derived key output` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `derived key output` data into `deserialize_reader`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
