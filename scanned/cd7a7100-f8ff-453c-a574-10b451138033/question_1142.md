# Q1142: parameter boundary in gas_counter::pay_per

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling inputs at the exact boundary of a cost parameter's applicability, drive `runtime/near-vm-runner/src/logic/gas_counter.rs::pay_per` to pay a cheaper parameter than the executed work requires, breaking the invariant that each unit of work is charged under the parameter that governs it, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/gas_counter.rs` -> `pay_per`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: inputs at the exact boundary of a cost parameter's applicability
- Exploit idea: pay a cheaper parameter than the executed work requires
- Invariant to test: each unit of work is charged under the parameter that governs it
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
