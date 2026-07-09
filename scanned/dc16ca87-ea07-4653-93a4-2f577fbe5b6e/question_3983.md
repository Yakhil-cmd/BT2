# Q3983: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `hash output` so `set_non_identity_constant` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Pass non-canonical or edge-case encodings of `hash output` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `hash output` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `hash output` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
