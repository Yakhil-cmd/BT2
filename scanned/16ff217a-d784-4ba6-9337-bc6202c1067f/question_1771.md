# Q1771: promise-yield resume abuse in receipt_manager::create_promise_resume_receipt

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling the data id and timeout of a yielded promise, drive `runtime/runtime/src/receipt_manager.rs::create_promise_resume_receipt` to resume or expire a yielded promise belonging to another account's call, breaking the invariant that only the contract that created a yielded promise can resume it, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/receipt_manager.rs` -> `create_promise_resume_receipt`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: the data id and timeout of a yielded promise
- Exploit idea: resume or expire a yielded promise belonging to another account's call
- Invariant to test: only the contract that created a yielded promise can resume it
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
