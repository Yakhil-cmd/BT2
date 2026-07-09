# Q3856: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `polynomial commitment` so `eval_at_point` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Pass non-canonical or edge-case encodings of `polynomial commitment` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `polynomial commitment` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `polynomial commitment` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
