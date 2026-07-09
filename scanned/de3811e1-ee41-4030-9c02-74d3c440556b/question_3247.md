# Q3247: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and use multiple encodings of `hash_app_id_with_pk binding` so `HDKG` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::HDKG`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `m`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `hash_app_id_with_pk binding` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `hash_app_id_with_pk binding` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `HDKG`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
