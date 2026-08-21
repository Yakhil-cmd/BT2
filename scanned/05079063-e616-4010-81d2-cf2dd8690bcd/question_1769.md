# Q1769: deploy-contract size accounting in receipt_manager::append_use_deploy_global_contract

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling contract size close to `max_contract_size` and repeated redeploys, drive `runtime/runtime/src/receipt_manager.rs::append_use_deploy_global_contract` to pay for a small contract while a larger one is persisted and charged to storage, breaking the invariant that contract deployment charges by the exact byte length of the code that is stored, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/receipt_manager.rs` -> `append_use_deploy_global_contract`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: contract size close to `max_contract_size` and repeated redeploys
- Exploit idea: pay for a small contract while a larger one is persisted and charged to storage
- Invariant to test: contract deployment charges by the exact byte length of the code that is stored
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
