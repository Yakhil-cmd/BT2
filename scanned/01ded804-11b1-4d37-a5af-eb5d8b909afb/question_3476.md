# Q3476: Exploit non-canonical decoding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and use multiple encodings of `private share` so `derive_verifying_key` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Pass non-canonical or edge-case encodings of `private share` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `private share` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `private share` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
