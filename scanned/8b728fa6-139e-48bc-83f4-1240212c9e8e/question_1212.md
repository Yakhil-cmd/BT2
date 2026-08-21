# Q1212: memory grow accounting in logic::predecessor_account_id

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling repeated grow operations interleaved with host calls, drive `runtime/near-vm-runner/src/logic/logic.rs::predecessor_account_id` to grow memory without the corresponding gas charge, breaking the invariant that every memory page growth is charged before allocation, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `predecessor_account_id`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: repeated grow operations interleaved with host calls
- Exploit idea: grow memory without the corresponding gas charge
- Invariant to test: every memory page growth is charged before allocation
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
