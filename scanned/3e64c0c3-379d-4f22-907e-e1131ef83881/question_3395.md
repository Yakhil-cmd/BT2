# Q3395: receipt creation from contract in ext::submit_promise_resume_data_with_yield_id

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling the number, size and receiver of promises created in one call, drive `runtime/runtime/src/ext.rs::submit_promise_resume_data_with_yield_id` to create receipts whose combined cost exceeds what the call paid, breaking the invariant that a call pays for every receipt it creates before the receipt is queued, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `submit_promise_resume_data_with_yield_id`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: the number, size and receiver of promises created in one call
- Exploit idea: create receipts whose combined cost exceeds what the call paid
- Invariant to test: a call pays for every receipt it creates before the receipt is queued
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
