# Q3347: outgoing buffer bypass in congestion_control::safe_add_gas_to_u128

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipt sizes just under the per-shard buffer accounting granularity, drive `runtime/runtime/src/congestion_control.rs::safe_add_gas_to_u128` to exceed the outgoing buffer limits through rounding, breaking the invariant that buffered outgoing bytes and gas never exceed the configured limits, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/runtime/src/congestion_control.rs` -> `safe_add_gas_to_u128`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipt sizes just under the per-shard buffer accounting granularity
- Exploit idea: exceed the outgoing buffer limits through rounding
- Invariant to test: buffered outgoing bytes and gas never exceed the configured limits
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
