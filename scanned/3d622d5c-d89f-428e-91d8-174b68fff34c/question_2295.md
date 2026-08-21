# Q2295: flat storage panic in trie_store::decrement_refcount_by

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling key and delta shapes at the internal boundaries, drive `core/store/src/adapter/trie_store.rs::decrement_refcount_by` to panic inside flat storage on attacker-reachable state, breaking the invariant that flat storage handles all reachable state without panicking, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/store/src/adapter/trie_store.rs` -> `decrement_refcount_by`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: key and delta shapes at the internal boundaries
- Exploit idea: panic inside flat storage on attacker-reachable state
- Invariant to test: flat storage handles all reachable state without panicking
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
