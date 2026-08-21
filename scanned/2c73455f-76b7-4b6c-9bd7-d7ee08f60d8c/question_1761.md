# Q1761: actor-permission bypass in receipt_manager::append_action_delete_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling receipt predecessor and receiver ids crafted via cross-contract calls, drive `runtime/runtime/src/receipt_manager.rs::append_action_delete_key` to perform an account-mutating action on an account whose key never authorised it, breaking the invariant that only the account itself, or its authorised key, may mutate its own account record, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/receipt_manager.rs` -> `append_action_delete_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: receipt predecessor and receiver ids crafted via cross-contract calls
- Exploit idea: perform an account-mutating action on an account whose key never authorised it
- Invariant to test: only the account itself, or its authorised key, may mutate its own account record
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
