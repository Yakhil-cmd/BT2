# Q1741: Exploit non-canonical decoding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and use multiple encodings of `coordinator-selected signer set` so `sign_v2` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `coordinator-selected signer set` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `coordinator-selected signer set` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
