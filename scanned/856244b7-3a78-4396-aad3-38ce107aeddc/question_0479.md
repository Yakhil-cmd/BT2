# Q479: column separator confusion in trie_key::extend

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling storage keys containing the bytes used as internal separators, drive `core/primitives/src/trie_key.rs::extend` to cross from one key column into another, breaking the invariant that column tags cannot be forged from user-controlled key bytes, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives/src/trie_key.rs` -> `extend`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: storage keys containing the bytes used as internal separators
- Exploit idea: cross from one key column into another
- Invariant to test: column tags cannot be forged from user-controlled key bytes
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
