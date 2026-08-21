# Q3378: promise dependency cycle in ext::create_promise_yield_receipt_with_id

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling promise dependency graphs with self-references or long chains, drive `runtime/runtime/src/ext.rs::create_promise_yield_receipt_with_id` to build a dependency structure the runtime cannot resolve or bound, breaking the invariant that promise graphs are acyclic and bounded per receipt, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `create_promise_yield_receipt_with_id`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: promise dependency graphs with self-references or long chains
- Exploit idea: build a dependency structure the runtime cannot resolve or bound
- Invariant to test: promise graphs are acyclic and bounded per receipt
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
