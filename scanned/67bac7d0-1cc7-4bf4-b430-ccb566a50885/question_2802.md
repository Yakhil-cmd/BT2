# Q2802: log flooding in dependencies::deref_removed_value_bytes

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling log message count and length at the configured limits, drive `runtime/near-vm-runner/src/logic/dependencies.rs::deref_removed_value_bytes` to emit more log bytes than the limits and charges permit, breaking the invariant that total log output is bounded and charged by its real byte length, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/dependencies.rs` -> `deref_removed_value_bytes`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: log message count and length at the configured limits
- Exploit idea: emit more log bytes than the limits and charges permit
- Invariant to test: total log output is bounded and charged by its real byte length
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
