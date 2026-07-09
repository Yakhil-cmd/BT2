# Q2162: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `polynomial` so `hash` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/hash.rs::hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Pass non-canonical or edge-case encodings of `polynomial` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `polynomial` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::hash::hash` that feeds crafted `polynomial` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
