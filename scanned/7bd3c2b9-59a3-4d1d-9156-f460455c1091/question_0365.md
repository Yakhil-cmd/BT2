# Q365: congestion info divergence in congestion_info::is_no

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling receipts that make computed and stored congestion info disagree, drive `core/primitives/src/congestion_info.rs::is_no` to have two nodes derive different congestion info for the same chunk, breaking the invariant that congestion info is a deterministic function of the shard's queues, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/congestion_info.rs` -> `is_no`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: receipts that make computed and stored congestion info disagree
- Exploit idea: have two nodes derive different congestion info for the same chunk
- Invariant to test: congestion info is a deterministic function of the shard's queues
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
