# Q7660: lookup partial encoded chunk from chunk storage state root consistency

## Question

What can an unprivileged user do by submitting transactions and contract calls that produce chunk transactions and outgoing receipts so that `lookup_partial_encoded_chunk_from_chunk_storage` in `chain/chunks/src/shards_manager_actor.rs` processes contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries along the chunk production, distribution, and validation path? User controls contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries -> `lookup_partial_encoded_chunk_from_chunk_storage` processes that value during TrieUpdate writes, flat-state reads, state sync proof assembly, and chunk extra/state-root computation -> the trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state invariant might break -> potential in-scope impact is state desynchronization, storage corruption, balance manipulation, or consensus flaw under the NEAR HackenProof scope. Exploit hypothesis: a user-controlled storage mutation can make this code commit a state root that disagrees with account storage accounting or flat-state contents, violating the actual protocol invariant that trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state.

## Target

- File/function: chain/chunks/src/shards_manager_actor.rs:1112::lookup_partial_encoded_chunk_from_chunk_storage
- Entrypoint: user transaction converted into chunk contents consumed by chain/chunks shard processing
- User-controlled input: contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries
- Attack path: User controls contract storage keys, account creation/deletion actions, receipts, trie proofs, and state-part boundaries -> public entrypoint reaches `lookup_partial_encoded_chunk_from_chunk_storage` -> TrieUpdate writes, flat-state reads, state sync proof assembly, and chunk extra/state-root computation handles the value -> invariant failure could produce state desynchronization, storage corruption, balance manipulation, or consensus flaw
- Security invariant: trie state, flat state, storage usage, and committed state roots represent the same deterministic post-state
- Expected bounty impact: state desynchronization, storage corruption, balance manipulation, or consensus flaw
- Fast validation approach: drive account/storage mutations through blocks, state sync, and restart paths while comparing trie root, flat state, storage usage, and execution outcomes
