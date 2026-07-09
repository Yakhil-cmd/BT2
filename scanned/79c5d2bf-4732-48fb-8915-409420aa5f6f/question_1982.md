# Q1982: Exploit non-canonical decoding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and use multiple encodings of `reshare` so `reshare` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Pass non-canonical or edge-case encodings of `reshare` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `reshare` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `reshare` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
