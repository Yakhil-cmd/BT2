# Q894: metadata desync in receipts_column_helper::trie_key

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipt append and pop sequences that stress outgoing metadata bookkeeping, drive `core/store/src/trie/receipts_column_helper.rs::trie_key` to desynchronise stored metadata from the real queue contents, breaking the invariant that queue metadata always matches the receipts actually stored, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/store/src/trie/receipts_column_helper.rs` -> `trie_key`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipt append and pop sequences that stress outgoing metadata bookkeeping
- Exploit idea: desynchronise stored metadata from the real queue contents
- Invariant to test: queue metadata always matches the receipts actually stored
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: write a `core/store` trie unit test over adversarial key/value pairs and assert lookups, deletes and refcounts stay consistent
