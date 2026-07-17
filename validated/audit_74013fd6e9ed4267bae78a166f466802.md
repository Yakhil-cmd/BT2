The code is now fully traced. Let me analyze the exact sequence.

Now I have the complete picture. Let me trace the exact index mismatch with concrete values from the `derive_impl` logic.

**Concrete trace of the bug:**

Pre-split layout (epoch N): `shard_ids = [0, 1, 2, 3]`, shard 1 at **index 1**.

After `derive_impl` splits shard 1 at boundary "ggg":
- `shard_ids` becomes `[0, 4, 5, 2, 3]` — shard 4 at index 1, shard 5 at **index 2**

In `ViewClientActor::handle(GetExecutionOutcome)`:
- `target_shard_id = 1` (pre-split, from `account_id_to_shard_id` using epoch N's layout)
- `target_shard_index = 1` (pre-split index, computed once, **never updated**)
- `get_next_block_hash_with_new_chunk` expands `shard_ids` to `[4, 5]`, iterates in order, returns `(h, 4)` — the first child with a new chunk — regardless of which child the receiver actually maps to
- If `receiver_id = "hhh"` (maps to shard 5 post-split), the outcome is in shard 5's chunk, but `target_shard_id` is shadowed to `4`
- `outcome_roots` from block `h` has 5 entries ordered by post-split layout
- `merklize(&outcome_roots).1[1]` = proof for shard 4's `prev_outcome_root` (index 1)
- Correct proof should be `merklize(&outcome_roots).1[2]` (shard 5, index 2)

The `target_shard_index` is computed from the pre-split layout and is never recomputed after `get_next_block_hash_with_new_chunk` returns a child shard from the post-split layout.

---

### Title
`GetExecutionOutcome` Returns Wrong `outcome_root_proof` Shard Index After Dynamic Resharding Split — (`chain/client/src/view_client_actor.rs`)

### Summary

`target_shard_index` is computed once from the pre-split epoch's shard layout and is never recomputed after `get_next_block_hash_with_new_chunk` returns a child shard from the post-split epoch. When the receipt's receiver maps to the **second** child shard after a split, `merklize(&outcome_roots).1[target_shard_index]` indexes the **first** child shard's `prev_outcome_root` instead of the second child's, returning a structurally valid Merkle proof that proves the wrong shard's outcome root.

### Finding Description

In `chain/client/src/view_client_actor.rs`, the `GetExecutionOutcome` handler computes `target_shard_index` using the shard layout of the epoch in which the outcome was recorded (the pre-split epoch): [1](#0-0) 

`target_shard_index` is then used — without being recomputed — to index into `outcome_roots` collected from block `h`, which belongs to the **post-split** epoch: [2](#0-1) 

`get_next_block_hash_with_new_chunk` expands the original `shard_id` to its children when crossing an epoch boundary with a layout change: [3](#0-2) 

It returns the **first** child shard that has a new chunk, regardless of which child the receipt's receiver actually maps to. In `ShardLayoutV3::derive_impl`, a parent shard at index `k` is replaced by two children at indices `k` and `k+1`: [4](#0-3) [5](#0-4) 

When the receiver maps to the **second** child (post-split index `k+1`), `get_next_block_hash_with_new_chunk` still returns the first child (index `k`) because it iterates `shard_ids` in order. The stale `target_shard_index = k` then selects `outcome_roots[k]` — the first child's `prev_outcome_root` — instead of `outcome_roots[k+1]` (the second child's).

The bounds check at line 1174 does not catch this: after a split the `outcome_roots` vector is longer, so the old index `k` is still within bounds.

### Impact Explanation

The returned `outcome_root_proof` is a structurally valid Merkle path proving that the **wrong** child shard's `prev_outcome_root` is included in the block's `outcome_root`. A light client that receives this response and attempts to verify:

```
verify_path(block_header.outcome_root, outcome_root_proof, chunk_outcome_root)
```

will fail, because `chunk_outcome_root` (derived from the `outcome_proof` for the correct child shard) does not match the leaf the proof was built for. The `GetExecutionOutcome` RPC becomes permanently broken for any receipt whose receiver maps to the second child shard after a dynamic resharding split. The exact corrupted value is `merklize(&outcome_roots).1[target_shard_index]` where `target_shard_index` is off by one.

### Likelihood Explanation

Requires `ProtocolFeature::DynamicResharding` to be active and a shard split to have occurred. Once those conditions hold, any receipt whose receiver account falls in the upper half of the split parent shard's account range triggers the wrong index. This is a deterministic, reproducible condition — not a race or probabilistic event.

### Recommendation

After `get_next_block_hash_with_new_chunk` returns `(h, target_shard_id)`, recompute `target_shard_index` using the shard layout of block `h`'s epoch:

```rust
if let Some((h, target_shard_id)) = res {
    let h_epoch_id = *self.chain.get_block(&h)?.header().epoch_id();
    let h_shard_layout = self.epoch_manager.get_shard_layout(&h_epoch_id).into_chain_error()?;
    let target_shard_index = h_shard_layout
        .get_shard_index(target_shard_id)
        .map_err(Into::into)
        .into_chain_error()?;
    // ... rest of the handler
}
```

### Proof of Concept

1. Configure a test-loop environment with `DynamicResharding` enabled and a 4-shard layout (shards 0–3).
2. Submit a receipt whose `receiver_id` maps to shard 1 (pre-split).
3. Trigger a shard split of shard 1 into children 4 ("lower half") and 5 ("upper half") at boundary "ggg".
4. Use a `receiver_id` such as `"hhh"` — which maps to shard 1 pre-split and to shard 5 post-split.
5. Call `GetExecutionOutcome { id: TransactionOrReceiptId::Receipt { receipt_id, receiver_id: "hhh" } }`.
6. Assert that `outcome_root_proof` is the proof for `outcome_roots[2]` (shard 5, index 2 in post-split), not `outcome_roots[1]` (shard 4, index 1).
7. Observe that `verify_path(block_header.outcome_root, outcome_root_proof, chunk_outcome_root)` returns `false`, confirming the wrong index is used.

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

**File:** chain/chain/src/chain.rs (L3917-3944)
```rust
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

**File:** core/primitives/src/shard_layout/v3.rs (L258-282)
```rust
    fn derive_impl(
        mut shard_ids: Vec<ShardId>,
        mut boundary_accounts: Vec<AccountId>,
        new_boundary_account: AccountId,
        mut shards_split_map: ShardsSplitMapV3,
    ) -> Result<Self, ShardLayoutError> {
        let Err(new_boundary_idx) = boundary_accounts.binary_search(&new_boundary_account) else {
            return Err(ShardLayoutError::DuplicateBoundaryAccount {
                account_id: new_boundary_account,
            });
        };
        boundary_accounts.insert(new_boundary_idx, new_boundary_account);

        let max_shard_id =
            *shard_ids.iter().max().expect("there should always be at least one shard");
        let new_shards = vec![max_shard_id + 1, max_shard_id + 2];

        let [last_split] = shard_ids
            .splice(new_boundary_idx..new_boundary_idx + 1, new_shards.clone())
            .collect_array()
            .expect("should only splice one shard");
        shards_split_map.insert(last_split, new_shards);

        Ok(Self::new(boundary_accounts, shard_ids, shards_split_map, last_split))
    }
```
