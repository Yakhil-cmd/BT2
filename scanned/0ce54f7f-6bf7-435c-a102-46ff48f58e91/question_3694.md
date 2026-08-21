# Q3694: integer overflow in host args in logic::get_public_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling length and offset arguments summing past the integer bound, drive `runtime/near-vm-runner/src/logic/logic.rs::get_public_key` to wrap an offset or length computation into an in-bounds check, breaking the invariant that host argument arithmetic uses checked operations everywhere, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `get_public_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: length and offset arguments summing past the integer bound
- Exploit idea: wrap an offset or length computation into an in-bounds check
- Invariant to test: host argument arithmetic uses checked operations everywhere
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
