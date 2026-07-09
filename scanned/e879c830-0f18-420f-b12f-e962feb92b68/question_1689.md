# Q1689: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and use multiple encodings of `presignature context` so `construct_key_package` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `presignature context` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `presignature context` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
