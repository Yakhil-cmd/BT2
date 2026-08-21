# Q2834: gas limit vs deadline in gas_counter::before_loading_executable

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling work whose wall-clock cost is far above its gas cost, drive `runtime/near-vm-runner/src/logic/gas_counter.rs::before_loading_executable` to exceed the block's real time budget while staying inside the gas budget, breaking the invariant that gas cost is proportional to real execution time on reference hardware, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/gas_counter.rs` -> `before_loading_executable`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: work whose wall-clock cost is far above its gas cost
- Exploit idea: exceed the block's real time budget while staying inside the gas budget
- Invariant to test: gas cost is proportional to real execution time on reference hardware
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
