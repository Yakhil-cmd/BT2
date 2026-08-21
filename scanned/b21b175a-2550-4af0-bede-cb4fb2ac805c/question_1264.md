# Q1264: memory bounds check in logic::sha3_384

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling pointer and length arguments at, around and beyond the memory bounds, drive `runtime/near-vm-runner/src/logic/logic.rs::sha3_384` to read or write guest memory outside the allocated region, breaking the invariant that every host memory access is bounds-checked against the current memory size, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `sha3_384`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: pointer and length arguments at, around and beyond the memory bounds
- Exploit idea: read or write guest memory outside the allocated region
- Invariant to test: every host memory access is bounds-checked against the current memory size
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
