# Q1945: length-prefix confusion in signature::decode_bs58

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling element counts that disagree with the supplied buffer length, drive `core/crypto/src/signature.rs::decode_bs58` to read past the supplied buffer during element parsing, breaking the invariant that declared element counts are validated against the real buffer length, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/crypto/src/signature.rs` -> `decode_bs58`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: element counts that disagree with the supplied buffer length
- Exploit idea: read past the supplied buffer during element parsing
- Invariant to test: declared element counts are validated against the real buffer length
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
