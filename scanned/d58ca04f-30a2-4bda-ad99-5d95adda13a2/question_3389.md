# Q3389: storage remove refund in ext::storage_get

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling write-then-remove cycles on large values, drive `runtime/runtime/src/ext.rs::storage_get` to reclaim more storage refund than was originally staked, breaking the invariant that storage refunds never exceed the storage cost originally paid, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `storage_get`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: write-then-remove cycles on large values
- Exploit idea: reclaim more storage refund than was originally staked
- Invariant to test: storage refunds never exceed the storage cost originally paid
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
