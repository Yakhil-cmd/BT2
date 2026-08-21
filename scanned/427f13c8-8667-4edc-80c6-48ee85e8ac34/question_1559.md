# Q1559: storage-usage underflow in actions::clear_account_contract_storage_usage

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling account state writes and deletes interleaved with contract redeploys, drive `runtime/runtime/src/actions.rs::clear_account_contract_storage_usage` to drive `storage_usage` below the true byte count so the account escapes storage staking, breaking the invariant that an account's recorded `storage_usage` always equals the real serialized size of its state, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/actions.rs` -> `clear_account_contract_storage_usage`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: account state writes and deletes interleaved with contract redeploys
- Exploit idea: drive `storage_usage` below the true byte count so the account escapes storage staking
- Invariant to test: an account's recorded `storage_usage` always equals the real serialized size of its state
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
