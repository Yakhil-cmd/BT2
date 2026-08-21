# Q2241: key parsing round-trip in trie_key::extend

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling keys near the decoder's boundary conditions, drive `core/primitives/src/trie_key.rs::extend` to parse a key back into a different logical key than it encoded, breaking the invariant that key encode/decode round-trips exactly for every valid key, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/trie_key.rs` -> `extend`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: keys near the decoder's boundary conditions
- Exploit idea: parse a key back into a different logical key than it encoded
- Invariant to test: key encode/decode round-trips exactly for every valid key
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
