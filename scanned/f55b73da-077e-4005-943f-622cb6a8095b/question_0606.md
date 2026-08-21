# Q606: delta accumulation in trie_store::set_shard_uid_mapping

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a high write rate targeting one shard's flat deltas, drive `core/store/src/adapter/trie_store.rs::set_shard_uid_mapping` to grow in-memory deltas without bound at a cost below the damage, breaking the invariant that flat storage deltas are bounded by the paid-for write volume, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `core/store/src/adapter/trie_store.rs` -> `set_shard_uid_mapping`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a high write rate targeting one shard's flat deltas
- Exploit idea: grow in-memory deltas without bound at a cost below the damage
- Invariant to test: flat storage deltas are bounded by the paid-for write volume
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: write a multi-shard `test-loop-tests` scenario and assert every shard keeps producing chunks and all receipts drain
