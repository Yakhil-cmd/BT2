# Q1646: panic on queue boundary in congestion_control::upper_bound_len

## Question
Can an unprivileged attacker who drives cross-shard traffic from many attacker-funded accounts on different shards, controlling queue indices at their first, last and wrapped positions, drive `runtime/runtime/src/congestion_control.rs::upper_bound_len` to panic while indexing or popping a receipt queue, breaking the invariant that queue index arithmetic never panics for any reachable state, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/runtime/src/congestion_control.rs` -> `upper_bound_len`
- Entrypoint: unprivileged attacker drives cross-shard traffic from many attacker-funded accounts on different shards
- Attacker controls: queue indices at their first, last and wrapped positions
- Exploit idea: panic while indexing or popping a receipt queue
- Invariant to test: queue index arithmetic never panics for any reachable state
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
