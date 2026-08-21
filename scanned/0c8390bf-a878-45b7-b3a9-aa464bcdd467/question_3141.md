# Q3141: compiled cache key collision in logic::promise_batch_action_use_global_contract_impl

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling two distinct contracts whose cache keys can coincide, drive `runtime/near-vm-runner/src/wasmtime_runner/logic.rs::promise_batch_action_use_global_contract_impl` to execute compiled code belonging to a different contract, breaking the invariant that the compilation cache key uniquely determines the compiled artifact, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` -> `promise_batch_action_use_global_contract_impl`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: two distinct contracts whose cache keys can coincide
- Exploit idea: execute compiled code belonging to a different contract
- Invariant to test: the compilation cache key uniquely determines the compiled artifact
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
