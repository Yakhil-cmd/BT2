# Q1612: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and use multiple encodings of `presign package` so `compute_signature_share` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `presign package` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `presign package` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign package` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
