# Q2600: deep path amplification in shard_tries::apply_all_inner

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling keys sharing long prefixes to maximise trie depth, drive `core/store/src/trie/shard_tries.rs::apply_all_inner` to force deep traversals whose cost the charge does not reflect, breaking the invariant that traversal cost is charged per node actually visited, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/trie/shard_tries.rs` -> `apply_all_inner`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: keys sharing long prefixes to maximise trie depth
- Exploit idea: force deep traversals whose cost the charge does not reflect
- Invariant to test: traversal cost is charged per node actually visited
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
