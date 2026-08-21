# Q2655: witness limit wedge in trie_recording::get_subtree_root_by_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a single receipt whose minimum witness exceeds the limit, drive `core/store/src/trie/trie_recording.rs::get_subtree_root_by_key` to create a receipt that can never be included in a valid chunk, breaking the invariant that every accepted receipt can be executed within the witness limit, and leading to permanent freezing of funds?

## Target
- File/function: `core/store/src/trie/trie_recording.rs` -> `get_subtree_root_by_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a single receipt whose minimum witness exceeds the limit
- Exploit idea: create a receipt that can never be included in a valid chunk
- Invariant to test: every accepted receipt can be executed within the witness limit
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
