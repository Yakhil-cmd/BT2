# Q2366: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `polynomial commitment` so `verify` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Pass non-canonical or edge-case encodings of `polynomial commitment` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `polynomial commitment` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `polynomial commitment` / `verify` inputs, then assert whether downstream verification accepts an output that should have been rejected.
