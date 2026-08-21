# Q1985: free gas via refund in cost::gas

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling refund chains across several cross-shard hops, drive `core/parameters/src/cost.rs::gas` to receive back more gas value than was originally paid, breaking the invariant that refunded gas value never exceeds the value originally prepaid, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/parameters/src/cost.rs` -> `gas`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: refund chains across several cross-shard hops
- Exploit idea: receive back more gas value than was originally paid
- Invariant to test: refunded gas value never exceeds the value originally prepaid
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
