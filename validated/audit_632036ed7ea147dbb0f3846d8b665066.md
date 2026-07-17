Looking at the actual code in `chain/client/src/view_client_actor.rs` and `chain/chain/src/chain.rs`, I need to trace the exact data flow through `GetExecutionOutcome` across a resharding epoch boundary.

**Step 1 — `target_shard_index` is computed from the old epoch's layout:** [1](#0-0) 

`epoch_id` is the epoch of the outcome block (old epoch). `shard_layout` and `target_shard_index` are derived from that old layout.

**Step 2 — `get_next_block_hash_with_new_chunk` crosses the epoch boundary:** [2](#0-1) 

When the next block is in a new epoch with a different shard layout, `shard_ids` is updated to the children shards in the new layout, and the returned `shard_id` is the new epoch's child shard ID. The function correctly tracks the new layout internally.

**Step 3 — Back in the handler, `target_shard_id` is shadowed but `target_shard_index` is NOT updated:** [3](#0-2) 

`outcome_roots` is collected from block `h` (new epoch, new shard count). But `target_shard_index` is still the index from the **old** epoch's layout. The bounds check `target_shard_index >= outcome_roots.len()` only catches out-of-bounds, not wrong-but-in-bounds indices.

**The concrete mismatch:**

In V3 layouts, `derive_impl` splices two children in place of the parent: [4](#0-3) 

If the parent shard was at index `i`, children occupy indices `i` and `i+1`, and every shard previously at index `j > i` shifts to `j+1`. So a shard that did **not** split but had a higher index than the split shard will have `old_index` ≠ `new_index`. The `target_shard_index` computed from the old layout is off by 1 for all such shards.

For V1 layouts the mismatch is even larger — a parent at index 1 can split into children at indices 3, 4, 5, while `target_shard_index` stays at 1.

**Triggering path (unprivileged):**

1. Any user sends a cross-shard transaction with `receiver_id` mapping to a shard whose index is **higher** than the shard that will be split.
2. The receipt executes in the old epoch.
3. The next-chunk block for that shard falls in the new epoch (after resharding).
4. User calls `EXPERIMENTAL_light_client_proof` / `GetExecutionOutcome` with `TransactionOrReceiptId::Receipt { receipt_id, receiver_id }`.
5. `target_shard_index` = old layout index (e.g., 2); new layout index = 3.
6. `merklize(&outcome_roots).1[2]` returns the Merkle proof for the **wrong** shard's `prev_outcome_root`.

The returned `outcome_root_proof` cannot verify `chunk_outcome_root` against the block header's `outcome_root` — the proof is for the wrong leaf position. The light client proof invariant is broken: a legitimately executed receipt produces an unverifiable proof.

---

### Title
Stale `target_shard_index` from pre-resharding epoch layout corrupts `outcome_root_proof` in `GetExecutionOutcome` — (`chain/client/src/view_client_actor.rs`)

### Summary
`GetExecutionOutcome` computes `target_shard_index` from the outcome block's (old) epoch shard layout, then calls `get_next_block_hash_with_new_chunk` which may return a block in a post-resharding epoch with a different chunk array. The index is never recomputed for the new layout, so `merklize(&outcome_roots).1[target_shard_index]` indexes the wrong position, producing an `outcome_root_proof` that fails light-client verification.

### Finding Description
In `ViewClientActor::handle(GetExecutionOutcome)`:

1. `target_shard_index` is derived from `shard_layout` of the **outcome block's epoch** (lines 1150–1158).
2. `get_next_block_hash_with_new_chunk` internally updates its shard tracking when crossing an epoch boundary with a layout change, returning a `(block_hash, new_child_shard_id)` pair from the **new** epoch.
3. `outcome_roots` is collected from that new-epoch block (lines 1167–1173), which has `N+1` chunks after a split.
4. `target_shard_index` is never recomputed for the new layout. For any shard whose index shifted upward due to the split (all shards with old index > split position), `merklize(&outcome_roots).1[target_shard_index]` selects the wrong leaf.

The bounds guard (`target_shard_index >= outcome_roots.len()`) only catches fully out-of-range indices; a shifted-by-1 index passes silently.

### Impact Explanation
The returned `outcome_root_proof` is a Merkle proof for the wrong position in the post-resharding block's chunk array. A light client calling `verify_path(block_outcome_root, outcome_root_proof, chunk_outcome_root)` will always fail for affected receipts. The light-client proof invariant — that `GetExecutionOutcome` returns a verifiable inclusion proof — is broken for any receipt whose `receiver_id` maps to a shard with a higher index than the split shard, when the next-chunk block falls in the new epoch.

### Likelihood Explanation
Triggered automatically on any resharding event (static or dynamic) for receipts executed in the last blocks of the old epoch. Any unprivileged user can craft such a receipt by choosing an appropriate `receiver_id`. Resharding is a planned protocol event on mainnet.

### Recommendation
After `get_next_block_hash_with_new_chunk` returns `(h, new_target_shard_id)`, recompute `target_shard_index` using the new block's epoch layout:

```rust
if let Some((h, target_shard_id)) = res {
    let new_epoch_id = *self.chain.get_block(&h)?.header().epoch_id();
    let new_shard_layout = self.epoch_manager.get_shard_layout(&new_epoch_id).into_chain_error()?;
    let target_shard_index = new_shard_layout
        .get_shard_index(target_shard_id)
        .map_err(Into::into)
        .into_chain_error()?;
    // ... rest of proof construction
}
```

### Proof of Concept
1. Configure a testnet with a V1→V2 or V2→V3 resharding scheduled at epoch boundary E.
2. In epoch E−1, send a cross-shard transaction with `receiver_id` mapping to a shard at index > split shard index (e.g., shard 2 when shard 1 will split).
3. Wait for the receipt to execute and for the next-chunk block to land in epoch E.
4. Call `GetExecutionOutcome` with the receipt's `receipt_id` and `receiver_id`.
5. Assert `verify_path(block_outcome_root, outcome_root_proof, chunk_outcome_root)` — it will return `false`, confirming the proof is for the wrong shard index.

### Citations

**File:** chain/client/src/view_client_actor.rs (L1148-1158)
```rust
                let epoch_id =
                    *self.chain.get_block(&outcome_proof.block_hash)?.header().epoch_id();
                let shard_layout =
                    self.epoch_manager.get_shard_layout(&epoch_id).into_chain_error()?;
                let target_shard_id =
                    account_id_to_shard_id(self.epoch_manager.as_ref(), &account_id, &epoch_id)
                        .into_chain_error()?;
                let target_shard_index = shard_layout
                    .get_shard_index(target_shard_id)
                    .map_err(Into::into)
                    .into_chain_error()?;
```

**File:** chain/client/src/view_client_actor.rs (L1163-1183)
```rust
                if let Some((h, target_shard_id)) = res {
                    outcome_proof.block_hash = h;
                    // Here we assume the number of shards is small so this reconstruction
                    // should be fast
                    let outcome_roots = self
                        .chain
                        .get_block(&h)?
                        .chunks()
                        .iter()
                        .map(|header| *header.prev_outcome_root())
                        .collect::<Vec<_>>();
                    if target_shard_index >= outcome_roots.len() {
                        return Err(GetExecutionOutcomeError::InconsistentState {
                            number_or_shards: outcome_roots.len(),
                            execution_outcome_shard_id: target_shard_id,
                        });
                    }
                    Ok(GetExecutionOutcomeResponse {
                        outcome_proof: outcome_proof.into(),
                        outcome_root_proof: merklize(&outcome_roots).1[target_shard_index].clone(),
                    })
```

**File:** chain/chain/src/chain.rs (L3915-3944)
```rust
        while let Ok(next_block_hash) = self.chain_store.get_next_block_hash(&block_hash) {
            let next_epoch_id = *self.get_block_header(&next_block_hash)?.epoch_id();
            if next_epoch_id != epoch_id {
                let next_shard_layout = self.epoch_manager.get_shard_layout(&next_epoch_id)?;
                if next_shard_layout != shard_layout {
                    shard_ids = shard_ids
                        .into_iter()
                        .flat_map(|id| {
                            next_shard_layout.get_children_shards_ids(id).unwrap_or_else(|| {
                                panic!("invalid shard layout {:?} because it does not contain children shards for parent shard {}", next_shard_layout, id)
                            })
                        })
                        .collect();

                    shard_layout = next_shard_layout;
                }
                epoch_id = next_epoch_id;
            }
            block_hash = next_block_hash;

            let block = self.get_block(&block_hash)?;
            let chunks = block.chunks();
            for &shard_id in &shard_ids {
                let shard_index = shard_layout.get_shard_index(shard_id)?;
                let chunk_header =
                    &chunks.get(shard_index).ok_or(Error::InvalidShardId(shard_id))?;
                if chunk_header.height_included() == block.header().height() {
                    return Ok(Some((block_hash, shard_id)));
                }
            }
```

**File:** core/primitives/src/shard_layout/v3.rs (L273-279)
```rust
        let new_shards = vec![max_shard_id + 1, max_shard_id + 2];

        let [last_split] = shard_ids
            .splice(new_boundary_idx..new_boundary_idx + 1, new_shards.clone())
            .collect_array()
            .expect("should only splice one shard");
        shards_split_map.insert(last_split, new_shards);
```
