# Q2033: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and use multiple encodings of `coordinator-selected signer set` so `assert_sign_inputs` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `coordinator-selected signer set` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `coordinator-selected signer set` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
