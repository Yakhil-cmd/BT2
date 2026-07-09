# Q1896: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and use multiple encodings of `app_id` so `compute_signature_share` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::compute_signature_share`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `app_id` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `app_id` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
