# Q2076: parameter boundary in gas::saturating_sub

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling inputs at the exact boundary of a cost parameter's applicability, drive `core/primitives-core/src/gas.rs::saturating_sub` to pay a cheaper parameter than the executed work requires, breaking the invariant that each unit of work is charged under the parameter that governs it, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives-core/src/gas.rs` -> `saturating_sub`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: inputs at the exact boundary of a cost parameter's applicability
- Exploit idea: pay a cheaper parameter than the executed work requires
- Invariant to test: each unit of work is charged under the parameter that governs it
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
