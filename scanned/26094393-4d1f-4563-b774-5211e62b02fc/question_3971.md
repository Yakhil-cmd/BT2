# Q3971: storage write accounting in ext::wrap_storage_error

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling key and value lengths at the configured storage limits, drive `runtime/runtime/src/ext.rs::wrap_storage_error` to write state whose charged cost is below the bytes actually persisted, breaking the invariant that every persisted byte is charged at the configured write and storage price, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `wrap_storage_error`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: key and value lengths at the configured storage limits
- Exploit idea: write state whose charged cost is below the bytes actually persisted
- Invariant to test: every persisted byte is charged at the configured write and storage price
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
