Now I have the full picture. Let me read the exact handler code and the `get_next_block_hash_with_new_chunk` function carefully to confirm the exact corruption path.

The code is fully traced. Let me now write the analysis.

---

### Title
Wrong Shard Used for Outcome Proof Construction When `sender_id` Does Not Match Actual Transaction Shard — (`chain/client/src/view_client_actor.rs`)

### Summary

The `Handler<GetExecutionOutcome>` implementation in `ViewClientActor` uses the caller-supplied `sender_id` (or `receiver_id` for receipts) to derive `target_shard_id` and `target_shard_index` for proof construction. It does **not** validate that this account maps to the same shard where the transaction actually executed. Because `chain.get_execution_outcome(&id)` looks up the outcome by hash alone, a caller who supplies a valid `transaction_hash` but a wrong `sender_id` (one that maps to a different shard) causes the handler to build and return a structurally wrong `GetExecutionOutcomeResponse`.

### Finding Description

The handler at [1](#0-0)  extracts `account_id` directly from the caller-supplied `sender_id` field and immediately uses it — without any cross-check against the stored outcome — to compute `target_shard_id`:

```rust
let (id, account_id) = match msg.id {
    TransactionOrReceiptId::Transaction { transaction_hash, sender_id } => {
        (transaction_hash, sender_id)   // sender_id is fully attacker-controlled
    }
    ...
};
match self.chain.get_execution_outcome(&id) {   // lookup by hash only
    Ok(outcome) => {
        ...
        let target_shard_id =
            account_id_to_shard_id(self.epoch_manager.as_ref(), &account_id, &epoch_id)
```

`chain.get_execution_outcome` at [2](#0-1)  finds the outcome purely by `id` (the transaction hash), ignoring `sender_id` entirely. Once the outcome is found, the wrong `target_shard_id` is fed into:

1. `get_next_block_hash_with_new_chunk(&outcome_proof.block_hash, target_shard_id)` — which walks forward from the outcome block looking for the first block that has a **new chunk for shard B** (the wrong shard). [3](#0-2) 

2. `outcome_proof.block_hash = h` — overwrites the block hash with the wrong block. [4](#0-3) 

3. `merklize(&outcome_roots).1[target_shard_index]` — produces the Merkle path for shard B's index in the wrong block's chunk list. [5](#0-4) 

The returned `GetExecutionOutcomeResponse` therefore contains:
- `outcome_proof.block_hash` → the next block with a new chunk for **shard B** (wrong block)
- `outcome_root_proof` → the Merkle path for **shard B's index** in that wrong block

The inner `outcome_proof.proof` (the per-shard Merkle path) is still the correct stored proof for shard A. The two-step verification formula from the light-client spec is:

```python
shard_outcome_root = compute_root(sha256(borsh(execution_outcome)), outcome_proof.proof)
block_outcome_root = compute_root(sha256(borsh(shard_outcome_root)), outcome_root_proof)
```

`shard_outcome_root` is the correct shard-A root, but `outcome_root_proof` is the path for shard B's index in a different block. The computed `block_outcome_root` will not equal `block_header_lite.inner_lite.outcome_root`, so **the proof fails `verify_path`**. [6](#0-5) 

This wrong proof is also what the production `EXPERIMENTAL_light_client_proof` / `light_client_proof` RPC endpoint returns, since it passes `id` directly to `GetExecutionOutcome` without any additional validation: [7](#0-6) 

### Impact Explanation

The exact corrupted values are:
- `outcome_proof.block_hash`: advanced to the wrong block (next block with new chunk for shard B instead of shard A)
- `outcome_root_proof`: Merkle path for shard B index instead of shard A index

Any client that performs the two-step proof verification (as documented and as done in the existing test at [8](#0-7) ) will detect the mismatch and reject the proof. Bridges and light clients that follow the protocol spec are therefore safe.

The impact is limited to consumers of the RPC that trust the returned `block_hash` or `outcome_root_proof` without re-verifying — for example, indexers recording block attribution, or wallets displaying "included in block X." These consumers would receive a wrong block reference and a wrong shard attribution for the transaction outcome.

### Likelihood Explanation

Triggering this requires only a valid `transaction_hash` (publicly observable on-chain) and a `sender_id` that maps to a different shard. No privileged access is needed. The `EXPERIMENTAL_light_client_proof` RPC endpoint is publicly accessible. In a 2-shard network, any cross-shard transaction provides the necessary setup.

### Recommendation

Derive `target_shard_id` from the stored outcome itself (e.g., from `outcome_proof.outcome_with_id.outcome.executor_id` or from the shard recorded in the DB alongside the outcome), rather than from the caller-supplied `account_id`. The `sender_id` / `receiver_id` field in `TransactionOrReceiptId` should only be used for routing (deciding which node to forward the request to), not for proof construction.

### Proof of Concept

In a test-loop test with 2 shards:
1. Submit a transaction from `alice` (shard 0) to `bob` (shard 1).
2. Wait for the transaction to execute and finalize.
3. Call `GetExecutionOutcome { id: TransactionOrReceiptId::Transaction { transaction_hash: tx_hash, sender_id: bob } }` — correct hash, wrong sender.
4. The handler finds the outcome (alice's shard 0 execution), then computes `target_shard_id = shard_1` from `bob`, advances `block_hash` to the next block with a new chunk for shard 1, and returns `outcome_root_proof` for shard 1's index.
5. Assert `verify_path(block_header.outcome_root, outcome_root_proof, chunk_outcome_root)` returns `false` — confirming the returned proof is wrong.

The existing correct-case test at [9](#0-8)  can be adapted by substituting the wrong `sender_id` to reproduce the failure.

### Citations

**File:** chain/client/src/view_client_actor.rs (L1137-1154)
```rust
        let (id, account_id) = match msg.id {
            TransactionOrReceiptId::Transaction { transaction_hash, sender_id } => {
                (transaction_hash, sender_id)
            }
            TransactionOrReceiptId::Receipt { receipt_id, receiver_id } => {
                (receipt_id, receiver_id)
            }
        };
        match self.chain.get_execution_outcome(&id) {
            Ok(outcome) => {
                let mut outcome_proof = outcome;
                let epoch_id =
                    *self.chain.get_block(&outcome_proof.block_hash)?.header().epoch_id();
                let shard_layout =
                    self.epoch_manager.get_shard_layout(&epoch_id).into_chain_error()?;
                let target_shard_id =
                    account_id_to_shard_id(self.epoch_manager.as_ref(), &account_id, &epoch_id)
                        .into_chain_error()?;
```

**File:** chain/client/src/view_client_actor.rs (L1163-1164)
```rust
                if let Some((h, target_shard_id)) = res {
                    outcome_proof.block_hash = h;
```

**File:** chain/client/src/view_client_actor.rs (L1180-1183)
```rust
                    Ok(GetExecutionOutcomeResponse {
                        outcome_proof: outcome_proof.into(),
                        outcome_root_proof: merklize(&outcome_roots).1[target_shard_index].clone(),
                    })
```

**File:** chain/chain/src/chain.rs (L3904-3947)
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
        }

        Ok(None)
```

**File:** chain/chain/src/chain.rs (L4024-4036)
```rust
    pub fn get_execution_outcome(
        &self,
        id: &CryptoHash,
    ) -> Result<ExecutionOutcomeWithIdAndProof, Error> {
        let outcomes = self.chain_store.get_outcomes_by_id(id)?;
        outcomes
            .into_iter()
            .find(|outcome| match self.get_block_header(&outcome.block_hash) {
                Ok(header) => self.is_on_current_chain(&header).unwrap_or(false),
                Err(_) => false,
            })
            .ok_or_else(|| Error::DBNotFoundErr(format!("EXECUTION OUTCOME: {}", id)))
    }
```

**File:** core/primitives/src/merkle.rs (L112-119)
```rust
/// Verify merkle path for given item and corresponding path.
pub fn verify_path<T: BorshSerialize>(root: MerkleHash, path: &MerklePath, item: T) -> bool {
    verify_hash(root, path, CryptoHash::hash_borsh(item))
}

pub fn verify_hash(root: MerkleHash, path: &MerklePath, item_hash: MerkleHash) -> bool {
    compute_root_from_path(path, item_hash) == root
}
```

**File:** chain/jsonrpc/src/lib.rs (L2355-2375)
```rust
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
