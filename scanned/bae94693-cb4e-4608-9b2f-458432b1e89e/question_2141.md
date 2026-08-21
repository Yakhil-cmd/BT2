# Q2141: permanent congestion lock in congestion_info::missed_chunks_congestion

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling a burst that pushes a shard past the point where it can accept the receipts needed to drain, drive `core/primitives/src/congestion_info.rs::missed_chunks_congestion` to wedge a shard into a state where it can never drain its own queues, breaking the invariant that a congested shard always retains a path back to an uncongested state, and leading to permanent freezing of funds?

## Target
- File/function: `core/primitives/src/congestion_info.rs` -> `missed_chunks_congestion`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: a burst that pushes a shard past the point where it can accept the receipts needed to drain
- Exploit idea: wedge a shard into a state where it can never drain its own queues
- Invariant to test: a congested shard always retains a path back to an uncongested state
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
