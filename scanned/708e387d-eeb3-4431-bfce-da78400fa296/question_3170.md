# Q3170: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and use multiple encodings of `app_pk` so `deserialize` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `deserializer`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `app_pk` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `app_pk` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `deserialize`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
