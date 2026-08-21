# Q3360: trie update rollback in ext::append_action_add_key_with_full_access

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a call that writes heavily then fails, drive `runtime/runtime/src/ext.rs::append_action_add_key_with_full_access` to persist writes from a receipt whose outcome is failure, breaking the invariant that a failed receipt's trie updates are fully rolled back, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `append_action_add_key_with_full_access`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a call that writes heavily then fails
- Exploit idea: persist writes from a receipt whose outcome is failure
- Invariant to test: a failed receipt's trie updates are fully rolled back
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
