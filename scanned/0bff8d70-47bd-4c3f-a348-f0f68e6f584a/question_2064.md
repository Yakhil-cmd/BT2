# Q2064: gas price manipulation in gas::checked_add

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling transaction timing across gas price adjustments, drive `core/primitives-core/src/gas.rs::checked_add` to execute work at a materially lower gas price than the executing block's, breaking the invariant that fees are charged at the executing block's gas price, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives-core/src/gas.rs` -> `checked_add`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: transaction timing across gas price adjustments
- Exploit idea: execute work at a materially lower gas price than the executing block's
- Invariant to test: fees are charged at the executing block's gas price
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
