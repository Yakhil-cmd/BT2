# Q755: memtrie/disk divergence in mod::new_with_memtries

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling write patterns applied through both the memtrie and the disk trie, drive `core/store/src/trie/mod.rs::new_with_memtries` to have memtrie and disk trie compute different roots for one update, breaking the invariant that memtrie and disk trie always agree on the resulting state root, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/store/src/trie/mod.rs` -> `new_with_memtries`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: write patterns applied through both the memtrie and the disk trie
- Exploit idea: have memtrie and disk trie compute different roots for one update
- Invariant to test: memtrie and disk trie always agree on the resulting state root
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
