# Q1607: gas price rounding in config::permission_send_fees

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling transactions timed across a gas price change boundary, drive `runtime/runtime/src/config.rs::permission_send_fees` to pay at a stale gas price while execution charges at another, breaking the invariant that fees are always computed at the gas price of the block that executes them, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/config.rs` -> `permission_send_fees`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: transactions timed across a gas price change boundary
- Exploit idea: pay at a stale gas price while execution charges at another
- Invariant to test: fees are always computed at the gas price of the block that executes them
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
