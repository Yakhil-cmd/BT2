# Q956: free witness growth in trie_recording::get_trie_nodes_count

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling cheap host calls that each pull in large trie nodes, drive `core/store/src/trie/trie_recording.rs::get_trie_nodes_count` to impose witness bandwidth cost on validators far above the fee paid, breaking the invariant that witness bytes are charged to the receipt that causes them, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/trie/trie_recording.rs` -> `get_trie_nodes_count`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: cheap host calls that each pull in large trie nodes
- Exploit idea: impose witness bandwidth cost on validators far above the fee paid
- Invariant to test: witness bytes are charged to the receipt that causes them
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
