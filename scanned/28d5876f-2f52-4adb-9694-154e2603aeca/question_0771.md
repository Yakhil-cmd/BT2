# Q771: stale storage read in mod::recording_reads_with_recorder

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling reads racing a write within the same receipt, drive `core/store/src/trie/mod.rs::recording_reads_with_recorder` to observe pre-write state after a write in the same receipt, breaking the invariant that reads always observe the writes of the same receipt, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/store/src/trie/mod.rs` -> `recording_reads_with_recorder`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: reads racing a write within the same receipt
- Exploit idea: observe pre-write state after a write in the same receipt
- Invariant to test: reads always observe the writes of the same receipt
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
