# Q378: free receipt admission in congestion_info::remove_delayed_receipt_gas

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipts whose admitted size is larger than the size charged for, drive `core/primitives/src/congestion_info.rs::remove_delayed_receipt_gas` to admit receipts into a queue without paying their queueing cost, breaking the invariant that queued bytes and gas are fully paid for at admission, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives/src/congestion_info.rs` -> `remove_delayed_receipt_gas`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipts whose admitted size is larger than the size charged for
- Exploit idea: admit receipts into a queue without paying their queueing cost
- Invariant to test: queued bytes and gas are fully paid for at admission
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
