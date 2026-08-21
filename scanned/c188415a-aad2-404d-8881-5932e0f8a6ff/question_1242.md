# Q1242: host function determinism in logic::promise_result

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling inputs whose host results could depend on host state or ordering, drive `runtime/near-vm-runner/src/logic/logic.rs::promise_result` to get results that differ between two honest executions, breaking the invariant that every host function is a deterministic function of its inputs and consensus state, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `promise_result`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: inputs whose host results could depend on host state or ordering
- Exploit idea: get results that differ between two honest executions
- Invariant to test: every host function is a deterministic function of its inputs and consensus state
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
