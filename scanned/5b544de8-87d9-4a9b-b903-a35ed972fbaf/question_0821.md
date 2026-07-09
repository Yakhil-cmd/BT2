# Q821: Exploit non-canonical decoding

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `message buffer` so `reliable_broadcast_send` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/protocol/echo_broadcast.rs::reliable_broadcast_send`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `wait`, `data`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `message buffer` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `message buffer` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message buffer` data into `reliable_broadcast_send`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
