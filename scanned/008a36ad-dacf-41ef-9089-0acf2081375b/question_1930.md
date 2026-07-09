# Q1930: Exploit non-canonical decoding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and use multiple encodings of `keygen` so `keygen` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Pass non-canonical or edge-case encodings of `keygen` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `keygen` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `keygen` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
