# Q1587: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and use multiple encodings of `rerandomized presignature` so `presign` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `rerandomized presignature` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `rerandomized presignature` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `rerandomized presignature` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
