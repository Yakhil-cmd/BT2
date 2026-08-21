# Q1744: refund receipt loss in pipelining::prepare_function_call

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a failing cross-shard call whose refund targets a deleted account, drive `runtime/runtime/src/pipelining.rs::prepare_function_call` to destroy or misroute a refund so the prepaid value disappears, breaking the invariant that every refund is either delivered or accounted to the burnt total, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/pipelining.rs` -> `prepare_function_call`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a failing cross-shard call whose refund targets a deleted account
- Exploit idea: destroy or misroute a refund so the prepaid value disappears
- Invariant to test: every refund is either delivered or accounted to the burnt total
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
