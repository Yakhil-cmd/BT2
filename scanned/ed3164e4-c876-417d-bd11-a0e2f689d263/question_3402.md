# Q3402: storage read amplification in function_call::apply_recorded_storage_garbage

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling key patterns that force deep trie traversals per read, drive `runtime/runtime/src/function_call.rs::apply_recorded_storage_garbage` to force far more node reads than the read cost charges, breaking the invariant that read cost scales with the trie nodes actually touched, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/function_call.rs` -> `apply_recorded_storage_garbage`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: key patterns that force deep trie traversals per read
- Exploit idea: force far more node reads than the read cost charges
- Invariant to test: read cost scales with the trie nodes actually touched
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
