# Q1429: uncharged compile on call in logic::promise_batch_action_function_call_weight

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a first call to a cold contract on a node with an empty cache, drive `runtime/near-vm-runner/src/wasmtime_runner/logic.rs::promise_batch_action_function_call_weight` to shift compilation cost onto nodes that never charged for it, breaking the invariant that compilation is charged to the receipt that triggers it, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` -> `promise_batch_action_function_call_weight`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a first call to a cold contract on a node with an empty cache
- Exploit idea: shift compilation cost onto nodes that never charged for it
- Invariant to test: compilation is charged to the receipt that triggers it
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
