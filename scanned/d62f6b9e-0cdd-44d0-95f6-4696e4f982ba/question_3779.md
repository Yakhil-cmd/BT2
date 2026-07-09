# Q3779: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `interpolation set` so `add` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::add`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `rhs`
- Exploit idea: Pass non-canonical or edge-case encodings of `interpolation set` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `interpolation set` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::add` that feeds crafted `interpolation set` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
