# Q2187: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `Lagrange coefficient` so `batch_compute_lagrange_coefficients` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Pass non-canonical or edge-case encodings of `Lagrange coefficient` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `Lagrange coefficient` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `Lagrange coefficient` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
