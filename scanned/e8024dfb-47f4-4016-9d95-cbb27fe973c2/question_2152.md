# Q2152: cross-shard fairness in congestion_info::set_allowed_shard

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling many attacker accounts spread over every shard targeting one victim shard, drive `core/primitives/src/congestion_info.rs::set_allowed_shard` to monopolise a victim shard's incoming capacity, breaking the invariant that incoming capacity is shared across sources rather than captured by one, and leading to permanent freezing of funds?

## Target
- File/function: `core/primitives/src/congestion_info.rs` -> `set_allowed_shard`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: many attacker accounts spread over every shard targeting one victim shard
- Exploit idea: monopolise a victim shard's incoming capacity
- Invariant to test: incoming capacity is shared across sources rather than captured by one
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
