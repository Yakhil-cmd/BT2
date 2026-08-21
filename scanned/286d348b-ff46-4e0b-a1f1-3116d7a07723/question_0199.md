# Q199: undercosted operation in parameter_table::from_str

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling workloads that maximise real cost per parameter unit, drive `core/parameters/src/parameter_table.rs::from_str` to obtain execution far cheaper than its real cost to the network, breaking the invariant that every parameter reflects the worst-case real cost of its operation, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/parameters/src/parameter_table.rs` -> `from_str`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: workloads that maximise real cost per parameter unit
- Exploit idea: obtain execution far cheaper than its real cost to the network
- Invariant to test: every parameter reflects the worst-case real cost of its operation
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
