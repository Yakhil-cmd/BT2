# Q3552: Exploit non-canonical decoding

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `outgoing` so `outgoing` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::outgoing`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `message buffer`, `round message`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `outgoing` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `outgoing` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `outgoing` data into `outgoing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
