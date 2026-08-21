# Q1708: free code storage in global_contracts::get_nonce

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling many accounts referencing one global contract, drive `runtime/runtime/src/global_contracts.rs::get_nonce` to persist contract bytes without any account paying their storage cost, breaking the invariant that every persisted byte of contract code is paid for at the storage price, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/global_contracts.rs` -> `get_nonce`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: many accounts referencing one global contract
- Exploit idea: persist contract bytes without any account paying their storage cost
- Invariant to test: every persisted byte of contract code is paid for at the storage price
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
