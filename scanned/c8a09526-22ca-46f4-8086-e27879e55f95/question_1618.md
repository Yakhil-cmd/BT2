# Q1618: balance checker bypass in config::total_send_fees

## Question
Can an unprivileged attacker who submits a single transaction carrying a large attacker-chosen batch of actions, controlling deposits, refunds and burnt gas summing to a value the checker rounds away, drive `runtime/runtime/src/config.rs::total_send_fees` to complete a chunk whose token totals do not balance, breaking the invariant that the total supply before and after chunk application differs only by burnt gas, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/config.rs` -> `total_send_fees`
- Entrypoint: unprivileged attacker submits a single transaction carrying a large attacker-chosen batch of actions
- Attacker controls: deposits, refunds and burnt gas summing to a value the checker rounds away
- Exploit idea: complete a chunk whose token totals do not balance
- Invariant to test: the total supply before and after chunk application differs only by burnt gas
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
