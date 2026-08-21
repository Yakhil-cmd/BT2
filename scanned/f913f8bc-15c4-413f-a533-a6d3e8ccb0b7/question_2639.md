# Q2639: memtrie/disk divergence in shard_tries::state_changes_into

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling write patterns applied through both the memtrie and the disk trie, drive `core/store/src/trie/shard_tries.rs::state_changes_into` to have memtrie and disk trie compute different roots for one update, breaking the invariant that memtrie and disk trie always agree on the resulting state root, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/store/src/trie/shard_tries.rs` -> `state_changes_into`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: write patterns applied through both the memtrie and the disk trie
- Exploit idea: have memtrie and disk trie compute different roots for one update
- Invariant to test: memtrie and disk trie always agree on the resulting state root
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
