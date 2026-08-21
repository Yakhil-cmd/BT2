# Q2563: root recomputation cost in prefetching_trie_storage::clear_data

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling updates spread to maximise dirty subtrees per receipt, drive `core/store/src/trie/prefetching_trie_storage.rs::clear_data` to make root recomputation cost far exceed the gas charged, breaking the invariant that root recomputation cost is bounded by the charged write cost, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/trie/prefetching_trie_storage.rs` -> `clear_data`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: updates spread to maximise dirty subtrees per receipt
- Exploit idea: make root recomputation cost far exceed the gas charged
- Invariant to test: root recomputation cost is bounded by the charged write cost
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
