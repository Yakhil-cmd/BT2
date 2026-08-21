# Q2678: arena exhaustion in trie_storage::check_cache_size

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling sustained state growth aimed at the memtrie arena, drive `core/store/src/trie/trie_storage.rs::check_cache_size` to exhaust or fragment the memtrie arena and stall the node, breaking the invariant that memtrie memory use is bounded by the paid-for state size, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/store/src/trie/trie_storage.rs` -> `check_cache_size`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: sustained state growth aimed at the memtrie arena
- Exploit idea: exhaust or fragment the memtrie arena and stall the node
- Invariant to test: memtrie memory use is bounded by the paid-for state size
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
