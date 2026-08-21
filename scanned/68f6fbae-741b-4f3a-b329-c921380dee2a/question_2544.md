# Q2544: congestion-driven fee spike in outgoing_metadata::load

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling sustained cheap load that inflates fees for everyone else, drive `core/store/src/trie/outgoing_metadata.rs::load` to raise the effective cost of the network far above the attacker's own spend, breaking the invariant that the cost of causing congestion scales with the damage it inflicts, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/trie/outgoing_metadata.rs` -> `load`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: sustained cheap load that inflates fees for everyone else
- Exploit idea: raise the effective cost of the network far above the attacker's own spend
- Invariant to test: the cost of causing congestion scales with the damage it inflicts
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
