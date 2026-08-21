# Q226: storage usage accounting in account::identifier_storage_usage

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling state writes, key deletions and contract redeploys, drive `core/primitives-core/src/account.rs::identifier_storage_usage` to leave `storage_usage` smaller than the account's real footprint, breaking the invariant that `storage_usage` equals the exact serialized size of the account's state, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives-core/src/account.rs` -> `identifier_storage_usage`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: state writes, key deletions and contract redeploys
- Exploit idea: leave `storage_usage` smaller than the account's real footprint
- Invariant to test: `storage_usage` equals the exact serialized size of the account's state
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
