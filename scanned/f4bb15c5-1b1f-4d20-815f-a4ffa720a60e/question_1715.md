# Q1715: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and use multiple encodings of `v1` so `sign_v1` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `v1` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `v1` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `v1` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
