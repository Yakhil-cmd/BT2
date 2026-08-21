# Q494: prefix ambiguity in trie_key::parse_account_id_prefix

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling account ids and key suffixes chosen so two logical keys serialize alike, drive `core/primitives/src/trie_key.rs::parse_account_id_prefix` to address another account's state through key prefix confusion, breaking the invariant that trie key serialization is injective across all key kinds, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives/src/trie_key.rs` -> `parse_account_id_prefix`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: account ids and key suffixes chosen so two logical keys serialize alike
- Exploit idea: address another account's state through key prefix confusion
- Invariant to test: trie key serialization is injective across all key kinds
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
