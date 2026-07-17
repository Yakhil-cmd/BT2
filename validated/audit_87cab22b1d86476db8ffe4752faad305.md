### Title
Stale `target_shard_index` After Resharding Produces Invalid `outcome_root_proof` in `GetExecutionOutcome` — (`chain/client/src/view_client_actor.rs`)

---

### Summary

`GetExecutionOutcome` computes `target_shard_index` once from the outcome block's epoch (E1) shard layout, then calls `get_next_block_hash_with_new_chunk` which may cross a resharding boundary and return a child shard ID in a new epoch (E2). The `outcome_roots` vector is then built from the E2 block's chunks (ordered by E2's shard layout), but the stale E1 `target_shard_index` is used to select the Merkle path. The result is an `outcome_root_proof` for the wrong shard, which fails `verify_path` against the block's outcome root.

---

### Finding Description

The handler for `GetExecutionOutcome` in `ViewClientActor` follows this sequence:

**Step 1 — index computed from E1:** [1](#0-0) 

`epoch_id` is taken from the outcome block (E1). `shard_layout` and `target_shard_index` are derived from E1's layout. `target_shard_index` is never updated after this point.

**Step 2 — `get_next_block_hash_with_new_chunk` may cross the epoch boundary:** [2](#0-1) 

When a resharding event is encountered, the function expands `shard_ids` to the children shards in E2's layout and returns `(block_in_E2, child_shard_id)`. Internally it correctly uses E2's `shard_layout.get_shard_index(shard_id)` to locate the chunk, but the caller never sees this updated layout.

**Step 3 — `outcome_roots` are from E2, indexed by E2's layout:** [3](#0-2) 

`target_shard_id` is shadowed with the child shard ID (E2), but `target_shard_index` remains the E1 value. `outcome_roots` is built from block `h`'s chunks, which are ordered by E2's shard layout. `merklize(&outcome_roots).1[target_shard_index]` therefore selects the Merkle path for the wrong position.

The block-level `outcome_root` is computed the same way — `merklize` over per-shard `prev_outcome_root` values ordered by the block's (E2) shard layout: [4](#0-3) 

So the path returned corresponds to a different shard's leaf than the one the light client needs to verify.

---

### Impact Explanation

Any unprivileged RPC caller that submits a `GetExecutionOutcome` (or the JSON-RPC `light_client_proof` wrapper) for a transaction or receipt whose outcome block is the last block of an epoch that is immediately followed by a resharding epoch receives an `outcome_root_proof` that is the Merkle path for the wrong shard index. `verify_path(block_outcome_root, outcome_root_proof, shard_outcome_root)` returns `false`. The light client proof is permanently broken for that outcome — there is no retry that fixes it because the node always recomputes the same wrong index.

The JSON-RPC surface that exposes this: [5](#0-4) 

---

### Likelihood Explanation

Requires a resharding event (epoch boundary with shard layout change) to occur between the outcome block and the next block that contains a new chunk for the affected shard. This is an infrequent but planned and production-occurring event on NEAR mainnet. Any transaction executed in the last block of a pre-resharding epoch is affected. No special privileges are required — any user can submit a transaction and query the proof.

---

### Recommendation

After `get_next_block_hash_with_new_chunk` returns `(h, new_target_shard_id)`, recompute `target_shard_index` using the epoch of block `h` and `new_target_shard_id`:

```rust
if let Some((h, target_shard_id)) = res {
    outcome_proof.block_hash = h;
    // Recompute index using the epoch of the proof block, not the outcome block
    let proof_epoch_id = *self.chain.get_block(&h)?.header().epoch_id();
    let proof_shard_layout = self.epoch_manager
        .get_shard_layout(&proof_epoch_id)
        .into_chain_error()?;
    let target_shard_index = proof_shard_layout
        .get_shard_index(target_shard_id)
        .map_err(Into::into)
        .into_chain_error()?;
    // ... rest unchanged
```

---

### Proof of Concept

1. Configure a test-loop with two epochs: E1 has N shards, E2 has N+1 shards (shard split at epoch boundary).
2. Submit a transaction in the last block of E1 so its outcome block is in E1.
3. Advance the chain into E2.
4. Call `GetExecutionOutcome` with the transaction hash and sender's `account_id`.
5. Retrieve the block referenced by `outcome_proof.block_hash` (which will be in E2).
6. Reconstruct `shard_outcome_root` from `outcome_proof.proof` and the outcome hashes.
7. Assert `verify_path(block.header.outcome_root, outcome_root_proof, shard_outcome_root)` — this assertion **fails** because `outcome_root_proof` is the path for the E1 shard index applied to E2's `outcome_roots` vector.

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

**File:** chain/chain/src/chain.rs (L3904-3944)
```rust
    pub fn get_next_block_hash_with_new_chunk(
        &self,
        block_hash: &CryptoHash,
        shard_id: ShardId,
    ) -> Result<Option<(CryptoHash, ShardId)>, Error> {
        let mut block_hash = *block_hash;
        let mut epoch_id = *self.get_block_header(&block_hash)?.epoch_id();
        let mut shard_layout = self.epoch_manager.get_shard_layout(&epoch_id)?;
        // this corrects all the shard where the original shard will split to if sharding changes
        let mut shard_ids = vec![shard_id];

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

**File:** core/primitives/src/block.rs (L828-830)
```rust
    pub fn compute_outcome_root(&self) -> CryptoHash {
        merklize(&self.iter().map(|chunk| *chunk.prev_outcome_root()).collect_vec()).0
    }
```

**File:** chain/jsonrpc/src/lib.rs (L2348-2376)
```rust
    async fn light_client_proof_local(
        &self,
        request: near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofRequest,
    ) -> Result<
        near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofResponse,
        near_jsonrpc_primitives::types::light_client::RpcLightClientProofError,
    > {
        let near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofRequest {
            id,
            light_client_head,
        } = request;

        let execution_outcome_proof: near_client_primitives::types::GetExecutionOutcomeResponse =
            self.view_client_send(GetExecutionOutcome { id }).await?;

        let block_proof: near_client_primitives::types::GetBlockProofResponse = self
            .view_client_send(GetBlockProof {
                block_hash: execution_outcome_proof.outcome_proof.block_hash,
                head_block_hash: light_client_head,
            })
            .await?;

        Ok(near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofResponse {
            outcome_proof: execution_outcome_proof.outcome_proof,
            outcome_root_proof: execution_outcome_proof.outcome_root_proof,
            block_header_lite: block_proof.block_header_lite,
            block_proof: block_proof.proof,
        })
    }
```
