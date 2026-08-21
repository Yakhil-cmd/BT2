# Q3991: gas-limit overshoot in lib::process_delayed_receipts

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling receipt sizes tuned so the last receipt straddles the chunk gas limit, drive `runtime/runtime/src/lib.rs::process_delayed_receipts` to process a receipt whose cost exceeds the remaining chunk gas budget, breaking the invariant that a chunk never burns more gas than its declared gas limit, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/runtime/src/lib.rs` -> `process_delayed_receipts`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: receipt sizes tuned so the last receipt straddles the chunk gas limit
- Exploit idea: process a receipt whose cost exceeds the remaining chunk gas budget
- Invariant to test: a chunk never burns more gas than its declared gas limit
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
