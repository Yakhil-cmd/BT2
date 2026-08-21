# Q3551: prepaid gas ceiling in gas::schema_name

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling prepaid gas at and beyond `max_total_prepaid_gas`, drive `core/primitives-core/src/gas.rs::schema_name` to exceed the total prepaid gas limit across a promise batch, breaking the invariant that total prepaid gas across a receipt never exceeds the configured maximum, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives-core/src/gas.rs` -> `schema_name`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: prepaid gas at and beyond `max_total_prepaid_gas`
- Exploit idea: exceed the total prepaid gas limit across a promise batch
- Invariant to test: total prepaid gas across a receipt never exceeds the configured maximum
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
