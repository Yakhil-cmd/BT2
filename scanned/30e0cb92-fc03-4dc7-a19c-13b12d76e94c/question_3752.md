# Q3752: register accounting in logic::random_seed

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling register ids and sizes near the configured register limits, drive `runtime/near-vm-runner/src/logic/logic.rs::random_seed` to exceed the register count or size limits without paying, breaking the invariant that register usage is bounded and charged by the configured limits, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `random_seed`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: register ids and sizes near the configured register limits
- Exploit idea: exceed the register count or size limits without paying
- Invariant to test: register usage is bounded and charged by the configured limits
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
