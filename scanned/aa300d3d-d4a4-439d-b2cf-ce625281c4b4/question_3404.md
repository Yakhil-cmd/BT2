# Q3404: data-id spoofing in function_call::record_contract_call

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling the data ids a contract declares it will receive, drive `runtime/runtime/src/function_call.rs::record_contract_call` to consume a data receipt intended for another call, breaking the invariant that data receipt ids bind to exactly one awaiting call, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/function_call.rs` -> `record_contract_call`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: the data ids a contract declares it will receive
- Exploit idea: consume a data receipt intended for another call
- Invariant to test: data receipt ids bind to exactly one awaiting call
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
