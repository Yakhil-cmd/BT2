# Q2896: host charge ordering in logic::get_public_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling arguments that make a host call do work before its charge is applied, drive `runtime/near-vm-runner/src/logic/logic.rs::get_public_key` to perform host work that is never billed when the call later fails, breaking the invariant that host functions charge before performing work, and the charge survives failure, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `get_public_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: arguments that make a host call do work before its charge is applied
- Exploit idea: perform host work that is never billed when the call later fails
- Invariant to test: host functions charge before performing work, and the charge survives failure
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
