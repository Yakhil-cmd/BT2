# Q3450: Exploit non-canonical decoding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and use multiple encodings of `derive` so `derive_signing_share` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Pass non-canonical or edge-case encodings of `derive` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `derive` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `derive` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
