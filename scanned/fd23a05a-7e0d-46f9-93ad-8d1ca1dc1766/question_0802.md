# Q802: squash/insert-delete asymmetry in insert_delete::calc_memory_usage_and_store

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling delete sequences leaving degenerate branch and extension nodes, drive `core/store/src/trie/ops/insert_delete.rs::calc_memory_usage_and_store` to reach a non-canonical trie shape with a different root, breaking the invariant that the trie shape after any update sequence is canonical, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/store/src/trie/ops/insert_delete.rs` -> `calc_memory_usage_and_store`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: delete sequences leaving degenerate branch and extension nodes
- Exploit idea: reach a non-canonical trie shape with a different root
- Invariant to test: the trie shape after any update sequence is canonical
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
