# Q3327: stuck cross-shard funds in congestion_control::buffer_receipt

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling a transfer receipt aimed at a shard the attacker keeps saturated, drive `runtime/runtime/src/congestion_control.rs::buffer_receipt` to strand a victim's value transfer in a queue indefinitely, breaking the invariant that value in flight is always eventually delivered or refunded, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/congestion_control.rs` -> `buffer_receipt`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: a transfer receipt aimed at a shard the attacker keeps saturated
- Exploit idea: strand a victim's value transfer in a queue indefinitely
- Invariant to test: value in flight is always eventually delivered or refunded
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
