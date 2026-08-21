# Q3663: utf8/utf16 decoding in logic::bls12381_pairing_check

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling malformed UTF-8 and UTF-16 byte sequences of maximal length, drive `runtime/near-vm-runner/src/logic/logic.rs::bls12381_pairing_check` to panic or overrun while decoding attacker bytes in a host call, breaking the invariant that string decoding rejects malformed input with a typed error, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `bls12381_pairing_check`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: malformed UTF-8 and UTF-16 byte sequences of maximal length
- Exploit idea: panic or overrun while decoding attacker bytes in a host call
- Invariant to test: string decoding rejects malformed input with a typed error
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
