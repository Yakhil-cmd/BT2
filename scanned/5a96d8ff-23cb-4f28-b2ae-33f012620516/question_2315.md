# Q2315: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `serialized group element` so `eval_interpolation` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Pass non-canonical or edge-case encodings of `serialized group element` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `serialized group element` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `serialized group element` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
