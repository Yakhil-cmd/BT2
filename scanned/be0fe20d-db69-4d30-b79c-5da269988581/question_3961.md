# Q3961: storage read amplification in ext::storage_has_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling key patterns that force deep trie traversals per read, drive `runtime/runtime/src/ext.rs::storage_has_key` to force far more node reads than the read cost charges, breaking the invariant that read cost scales with the trie nodes actually touched, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `storage_has_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: key patterns that force deep trie traversals per read
- Exploit idea: force far more node reads than the read cost charges
- Invariant to test: read cost scales with the trie nodes actually touched
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
