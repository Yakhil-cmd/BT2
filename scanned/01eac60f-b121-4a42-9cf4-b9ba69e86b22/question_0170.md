# Q170: send/exec fee split in config::storage_amount_per_byte

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling cross-shard actions where send and exec fees are charged on different shards, drive `core/parameters/src/config.rs::storage_amount_per_byte` to pay the send fee but escape the exec fee, breaking the invariant that send and exec fees are both charged exactly once per action, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/parameters/src/config.rs` -> `storage_amount_per_byte`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: cross-shard actions where send and exec fees are charged on different shards
- Exploit idea: pay the send fee but escape the exec fee
- Invariant to test: send and exec fees are both charged exactly once per action
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
