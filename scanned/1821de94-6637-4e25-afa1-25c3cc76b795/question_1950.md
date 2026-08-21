# Q1950: decoding panic in signature::from_random

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling truncated, oversized and malformed encodings of curve elements, drive `core/crypto/src/signature.rs::from_random` to panic inside a cryptographic host call, breaking the invariant that cryptographic decoding returns typed errors instead of panicking, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/crypto/src/signature.rs` -> `from_random`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: truncated, oversized and malformed encodings of curve elements
- Exploit idea: panic inside a cryptographic host call
- Invariant to test: cryptographic decoding returns typed errors instead of panicking
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
