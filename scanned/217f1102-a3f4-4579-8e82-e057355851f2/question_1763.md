# Q1763: global contract reference leak in receipt_manager::append_action_deploy_global_contract

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling a global contract identifier referenced by many accounts, drive `runtime/runtime/src/receipt_manager.rs::append_action_deploy_global_contract` to make an account reference code it never paid the storage cost for, breaking the invariant that every account referencing contract code is charged the configured cost for that reference, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/receipt_manager.rs` -> `append_action_deploy_global_contract`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: a global contract identifier referenced by many accounts
- Exploit idea: make an account reference code it never paid the storage cost for
- Invariant to test: every account referencing contract code is charged the configured cost for that reference
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
