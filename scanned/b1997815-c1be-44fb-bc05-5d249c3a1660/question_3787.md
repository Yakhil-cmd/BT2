# Q3787: uncounted recorded nodes in recorded_storage_counter::observe_size

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling reads that record nodes without incrementing the recorded counter, drive `runtime/near-vm-runner/src/logic/recorded_storage_counter.rs::observe_size` to record state that the size limiter never counts, breaking the invariant that every recorded byte is counted against the witness limit, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/recorded_storage_counter.rs` -> `observe_size`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: reads that record nodes without incrementing the recorded counter
- Exploit idea: record state that the size limiter never counts
- Invariant to test: every recorded byte is counted against the witness limit
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
