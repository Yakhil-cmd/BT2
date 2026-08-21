# Q419: receipt enum growth in receipt::set_receiver_id

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipt variants carrying maximally sized payloads, drive `core/primitives/src/receipt.rs::set_receiver_id` to create a receipt whose encoded size exceeds the enforced limit, breaking the invariant that receipt encoded size is bounded and charged, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives/src/receipt.rs` -> `set_receiver_id`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipt variants carrying maximally sized payloads
- Exploit idea: create a receipt whose encoded size exceeds the enforced limit
- Invariant to test: receipt encoded size is bounded and charged
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
