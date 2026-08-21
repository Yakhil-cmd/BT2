# Q1657: storage iteration cost in ext::append_action_add_key_with_full_access

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling prefix scans over attacker-populated key ranges, drive `runtime/runtime/src/ext.rs::append_action_add_key_with_full_access` to perform an unbounded iteration for a bounded charge, breaking the invariant that iteration is charged per key and per byte actually visited, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `append_action_add_key_with_full_access`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: prefix scans over attacker-populated key ranges
- Exploit idea: perform an unbounded iteration for a bounded charge
- Invariant to test: iteration is charged per key and per byte actually visited
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
