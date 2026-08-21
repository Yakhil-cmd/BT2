# Q940: unbounded value size in shard_tries::store

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling values near the maximum permitted length written repeatedly, drive `core/store/src/trie/shard_tries.rs::store` to persist values larger than the limit or below their charge, breaking the invariant that stored values respect the configured maximum and are fully charged, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/trie/shard_tries.rs` -> `store`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: values near the maximum permitted length written repeatedly
- Exploit idea: persist values larger than the limit or below their charge
- Invariant to test: stored values respect the configured maximum and are fully charged
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
