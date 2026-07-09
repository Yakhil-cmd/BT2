# Q2058: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `serialized group element` so `check` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Pass non-canonical or edge-case encodings of `serialized group element` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `serialized group element` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `serialized group element` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
