# Q1956: Exploit non-canonical decoding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and use multiple encodings of `derived signing share` so `refresh` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Pass non-canonical or edge-case encodings of `derived signing share` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `derived signing share` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `derived signing share` / `refresh` inputs, then assert whether downstream verification accepts an output that should have been rejected.
