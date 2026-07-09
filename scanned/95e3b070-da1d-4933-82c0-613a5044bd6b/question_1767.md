# Q1767: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and use multiple encodings of `signing nonces` so `presign` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `signing nonces` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `signing nonces` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
