# Q737: arena exhaustion in mod::get_optimized_ref

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling sustained state growth aimed at the memtrie arena, drive `core/store/src/trie/mod.rs::get_optimized_ref` to exhaust or fragment the memtrie arena and stall the node, breaking the invariant that memtrie memory use is bounded by the paid-for state size, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/store/src/trie/mod.rs` -> `get_optimized_ref`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: sustained state growth aimed at the memtrie arena
- Exploit idea: exhaust or fragment the memtrie arena and stall the node
- Invariant to test: memtrie memory use is bounded by the paid-for state size
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
