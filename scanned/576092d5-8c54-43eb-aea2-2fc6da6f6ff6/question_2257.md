# Q2257: key length inflation in trie_key::parse_data_id_from_received_data_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling maximum-length keys written in bulk, drive `core/primitives/src/trie_key.rs::parse_data_id_from_received_data_key` to persist keys whose stored length exceeds what was charged, breaking the invariant that key storage is charged by its exact persisted length, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives/src/trie_key.rs` -> `parse_data_id_from_received_data_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: maximum-length keys written in bulk
- Exploit idea: persist keys whose stored length exceeds what was charged
- Invariant to test: key storage is charged by its exact persisted length
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
