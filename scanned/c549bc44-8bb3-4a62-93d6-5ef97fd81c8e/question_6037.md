# Q6037: get shard uids to gc state root consistency

## Question

What can an unprivileged user do by submitting signed transactions that become chunk transactions and receipts in block public inputs so that `get_shard_uids_to_gc` in `chain/chain/src/garbage_collection.rs` processes contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries along the block, chunk, and runtime adapter processing path? User controls contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries -> `get_shard_uids_to_gc` processes that value during TrieUpdate writes, flat-state reads, state sync proof assembly, and chunk extra/state-root computation -> the trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state invariant might break -> potential in-scope impact is state desynchronization, storage corruption, balance manipulation, or consensus flaw under the NEAR HackenProof scope. Exploit hypothesis: a user-controlled storage mutation can make this code commit a state root that disagrees with account storage accounting or flat-state contents, violating the actual protocol invariant that trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state.

## Target

- File/function: chain/chain/src/garbage_collection.rs:604::get_shard_uids_to_gc
- Entrypoint: user transaction included in a block processed by chain/chain/src/chain.rs::Chain::start_process_block_async
- User-controlled input: contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries
- Attack path: User controls contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries -> public entrypoint reaches `get_shard_uids_to_gc` -> TrieUpdate writes, flat-state reads, state sync proof assembly, and chunk extra/state-root computation handles the value -> invariant failure could produce state desynchronization, storage corruption, balance manipulation, or consensus flaw
- Security invariant: trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state
- Expected bounty impact: state desynchronization, storage corruption, balance manipulation, or consensus flaw
- Fast validation approach: drive account/storage mutations through blocks, state sync, and restart paths while comparing trie root, flat state, storage usage, and execution outcomes
