# Q3461: access-key allowance drift in receipt_manager::append_action_add_key_with_function_call

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a function-call key whose allowance is nearly exhausted, plus refunds, drive `runtime/runtime/src/receipt_manager.rs::append_action_add_key_with_function_call` to spend more than the key's allowance by exploiting refund crediting order, breaking the invariant that the total value spent through a function-call key never exceeds its allowance, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/receipt_manager.rs` -> `append_action_add_key_with_function_call`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a function-call key whose allowance is nearly exhausted, plus refunds
- Exploit idea: spend more than the key's allowance by exploiting refund crediting order
- Invariant to test: the total value spent through a function-call key never exceeds its allowance
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
