# Q3986: unbounded queue growth in lib::merge

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling receipt production rate versus the shard's drain rate, drive `runtime/runtime/src/lib.rs::merge` to grow a persistent queue faster than it can drain at a cost far below the damage, breaking the invariant that persistent queues are bounded by the congestion parameters, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/lib.rs` -> `merge`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: receipt production rate versus the shard's drain rate
- Exploit idea: grow a persistent queue faster than it can drain at a cost far below the damage
- Invariant to test: persistent queues are bounded by the congestion parameters
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
