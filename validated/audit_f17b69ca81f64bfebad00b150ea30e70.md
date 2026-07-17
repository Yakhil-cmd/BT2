Let me look more carefully at the exact index computation and shard layout handling after the epoch boundary crossing.

The code is clear. Let me now confirm the exact index mismatch by checking how V2/V3 shard layouts assign indices to child shards after a split.

The code path is fully traced. The bug is concrete and unambiguous.

---

### Title
Stale `target_shard_index` from pre-split epoch used to index post-split `outcome_roots`, corrupting `outcome_root_proof` in `GetExecutionOutcomeResponse` — (`chain/client/src/view_client_actor.rs`)

### Summary

`ViewClientActor::handle(GetExecutionOutcome)` computes `target_shard_index` from the **old epoch's** `shard_layout` (the block where the outcome was recorded), then calls `get_next_block_hash_with_new_chunk`, which may walk across an epoch boundary and return a block in the **new, post-split epoch**. The `outcome_roots` vector is built from that new block (which has more shards), but the old, now-wrong `target_shard_index` is used unchanged to select the Merkle path element. In ShardLayoutV2/V3, shard IDs and shard indices are explicitly **not** the same, so the old index selects the wrong shard's `prev_outcome_root`, producing a structurally valid but semantically incorrect `outcome_root_proof`.

### Finding Description

In `view_client_actor.rs`, the handler for `GetExecutionOutcome`:

**Step 1 — index computed from OLD layout:** [1](#0-0) 

`epoch_id` is the epoch of the block where the outcome was stored (pre-split). `shard_layout` is the old layout. `target_shard_index` is the positional index of the parent shard in that old layout.

**Step 2 — `get_next_block_hash_with_new_chunk` crosses the epoch boundary:** [2](#0-1) 

When the next epoch has a different shard layout, `shard_ids` is expanded to child shards and `shard_layout` is updated to the new layout. The function returns `(h, child_shard_id)` where `h` is a block in the new epoch.

**Step 3 — `outcome_roots` built from the new block, but OLD index used:** [3](#0-2) 

`target_shard_id` is updated to the child shard ID (line 1163), but `target_shard_index` is **never recomputed**. `outcome_roots` has one entry per shard in the new layout (more entries than the old layout). The bounds check at line 1174 only catches the case where the old index exceeds the new count — it does not detect the silent wrong-shard selection when the old index is still in-bounds.

**Why the index is wrong in V2/V3:** [4](#0-3) 

In V2/V3, shard IDs and shard indices are decoupled. A concrete example from the test suite: old layout has shard ID 1 at some index; new layout has child shards 7 and 8 at indices 3 and 1 respectively (order determined by `shard_ids` array, not by ID value). [5](#0-4) 

Using the old index (e.g., 1) into the new `outcome_roots` (e.g., 4 entries) silently returns the outcome root of whichever shard happens to sit at that position in the new layout — not the child shard that actually executed the receipt.

### Impact Explanation

The `outcome_root_proof` field of `GetExecutionOutcomeResponse` is the Merkle path that proves a shard's outcome root is committed in the block-level `outcome_root`. Any light client or bridge that calls `EXPERIMENTAL_light_client_proof` and verifies:

```
block_outcome_root = compute_root(sha256(shard_outcome_root), outcome_root_proof)
```

will get a proof that does not reconstruct to the block's `outcome_root`, causing verification to fail. Bridges relying on nearcore's proof semantics to authorize cross-chain actions will reject valid proofs, breaking liveness for any outcome executed in the last block of a pre-split epoch. [6](#0-5) 

### Likelihood Explanation

The bug is triggered whenever:
1. A shard split occurs (epoch boundary with a new shard layout), and
2. A transaction or receipt is executed in the last block(s) of the pre-split epoch such that `get_next_block_hash_with_new_chunk` must walk into the post-split epoch to find the first new chunk.

Any unprivileged user can submit a transaction/receipt to an account in the splitting shard during the last epoch before a resharding event. No validator or operator privileges are required — the RPC endpoint `EXPERIMENTAL_light_client_proof` is publicly accessible.

### Recommendation

After `get_next_block_hash_with_new_chunk` returns `(h, target_shard_id)`, recompute `target_shard_index` using the **new block's epoch's shard layout** rather than the old one:

```rust
if let Some((h, target_shard_id)) = res {
    outcome_proof.block_hash = h;
    let new_epoch_id = *self.chain.get_block(&h)?.header().epoch_id();
    let new_shard_layout = self.epoch_manager.get_shard_layout(&new_epoch_id).into_chain_error()?;
    let target_shard_index = new_shard_layout
        .get_shard_index(target_shard_id)
        .map_err(Into::into)
        .into_chain_error()?;
    // ... build outcome_roots and use target_shard_index
}
```

### Proof of Concept

A test-loop test that:
1. Configures a genesis with a shard layout that will split at epoch 2 (e.g., shard 0 → shards 0 and 1).
2. Submits a receipt whose `receiver_id` maps to the splitting shard in the last block of epoch 1.
3. Advances the chain past the epoch boundary.
4. Calls `view_client.handle(GetExecutionOutcome { id: receipt_id, receiver_id })`.
5. Asserts `verify_path(block_outcome_root, outcome_root_proof, sha256(shard_outcome_root))` — this assertion will **fail** with the current code because `outcome_root_proof` is built using the old shard index into the new block's `outcome_roots`.

The existing test infrastructure in `test-loop-tests/src/tests/light_client.rs` (`check_outcome_proofs`) already performs exactly this verification and could be extended with a resharding scenario to reproduce the failure. [7](#0-6)

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

**File:** chain/chain/src/chain.rs (L3917-3931)
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
```

**File:** core/primitives/src/shard_layout/mod.rs (L376-381)
```rust
            // In V0 & V1 the shard id and shard index are the same.
            Self::V0(_) | Self::V1(_) => Ok(shard_id.into()),
            // In V2 & V3 the shard id and shard index are **not** the same.
            Self::V2(v2) => v2.get_shard_index(shard_id),
            Self::V3(v3) => v3.get_shard_index(shard_id),
        }
```

**File:** core/primitives/src/shard_layout/tests.rs (L140-156)
```rust
fn get_test_shard_layout_v2() -> ShardLayout {
    let b0 = "ccc".parse().unwrap();
    let b1 = "kkk".parse().unwrap();
    let b2 = "ppp".parse().unwrap();

    let boundary_accounts = vec![b0, b1, b2];
    let shard_ids = vec![3, 8, 4, 7];
    let shard_ids = new_shard_ids_vec(shard_ids);

    // the mapping from parent to the child
    // shard 1 is split into shards 7 & 8 while other shards stay the same
    let shards_split_map = BTreeMap::from([(1, vec![7, 8]), (3, vec![3]), (4, vec![4])]);
    let shards_split_map = new_shards_split_map_v2(shards_split_map);
    let shards_split_map = Some(shards_split_map);

    ShardLayout::v2(boundary_accounts, shard_ids, shards_split_map)
}
```

**File:** chain/jsonrpc/src/lib.rs (L2360-2375)
```rust
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
```

**File:** test-loop-tests/src/tests/light_client.rs (L303-359)
```rust
fn check_outcome_proofs(
    env: &mut TestLoopEnv,
    account_id: &AccountId,
    seed_hash: CryptoHash,
    tx: SignedTransaction,
) {
    let outcome = env.rpc_runner().execute_tx(tx, Duration::seconds(5)).unwrap();
    // Advance so the outcome's block is final and included in later blocks' merkle roots.
    env.rpc_runner().run_for_number_of_blocks(4);

    let mut ids = vec![TransactionOrReceiptId::Transaction {
        transaction_hash: outcome.transaction_outcome.id,
        sender_id: account_id.clone(),
    }];
    for receipt_outcome in &outcome.receipts_outcome {
        ids.push(TransactionOrReceiptId::Receipt {
            receipt_id: receipt_outcome.id,
            receiver_id: account_id.clone(),
        });
    }

    let mut rpc = env.rpc_node_mut();
    let view_client = rpc.view_client_actor();

    // The light client head and the block merkle root all proofs are checked against.
    let light_client_block = view_client
        .handle(GetNextLightClientBlock { last_block_hash: seed_hash })
        .unwrap()
        .unwrap();
    let light_client_head = light_client_block_hash(&light_client_block);
    let block_merkle_root = light_client_block.inner_lite.block_merkle_root;

    for id in ids {
        let execution_outcome = view_client.handle(GetExecutionOutcome { id }).unwrap();
        let outcome_proof = execution_outcome.outcome_proof;
        let block_proof = view_client
            .handle(GetBlockProof {
                block_hash: outcome_proof.block_hash,
                head_block_hash: light_client_head,
            })
            .unwrap();

        // outcome -> chunk outcome root -> block outcome root.
        let chunk_outcome_root =
            compute_root_from_path_and_item(&outcome_proof.proof, &outcome_proof.to_hashes());
        assert!(verify_path(
            block_proof.block_header_lite.inner_lite.outcome_root,
            &execution_outcome.outcome_root_proof,
            &chunk_outcome_root,
        ));

        // The light block header recomputes to the proof's block hash.
        assert_eq!(block_proof.block_header_lite.hash(), outcome_proof.block_hash);

        // block hash -> light client head's block merkle root.
        assert!(verify_hash(block_merkle_root, &block_proof.proof, outcome_proof.block_hash));
    }
```
