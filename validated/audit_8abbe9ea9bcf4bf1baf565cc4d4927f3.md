Based on my investigation of the code, I can trace the complete call path and assess the validity of this question.

## Code Path Analysis

**`is_block_executed` / `check_block_executed`** in `chain/chain/src/spice/chain.rs`: [1](#0-0) 

The function checks only `DBCol::ChunkExtra` presence for the given block hash — there is **no canonicality check**.

**`get_block_header_by_reference`** for `BlockId::Hash` in `view_client_actor.rs`: [2](#0-1) 

`self.chain.get_block_header(block_hash)` reads from `DBCol::BlockHeader`, which stores **all** block headers (canonical and fork). Then `check_block_executed` is the only gate — and it only checks `ChunkExtra` presence.

**`handle_query`** then uses the fork block's state root directly: [3](#0-2) 

**Fork blocks DO get `ChunkExtra` written in Spice mode.** The test `test_executing_forks` explicitly confirms this: [4](#0-3) 

The `SpiceChunkExecutorActor` executes all processed blocks, including fork blocks, and writes `ChunkExtra` for each.

## Assessment

The precondition is real and confirmed by production code and tests:
1. A fork block is processed → `SpiceChunkExecutorActor` executes it → `ChunkExtra` is written to `DBCol::ChunkExtra` keyed by the fork block hash.
2. The fork is abandoned (canonical chain moves elsewhere).
3. An attacker sends `Query { block_reference: BlockId::Hash(fork_hash), request: ViewAccount { ... } }`.
4. `get_block_header(fork_hash)` succeeds (fork header is in `DBCol::BlockHeader`).
5. `check_block_executed` finds `ChunkExtra` for the fork hash → returns `Ok(())`.
6. `get_chunk_extra(fork_hash, shard_uid)` returns the fork block's `ChunkExtra` with its state root.
7. `runtime.query(shard_uid, fork_state_root, ...)` returns account balance/state from the fork's trie.

**The exact corrupted value**: the account balance (or any state value) read from the fork block's state root, which may differ from the canonical chain's state at the same height if the fork applied different transactions.

**Contrast with non-Spice**: In non-Spice mode, `ChunkExtra` is only written for canonical blocks (synchronous execution), so querying a fork block by hash would fail at `get_chunk_extra` with `UnavailableShard`. In Spice mode, this implicit canonicality guard is absent.

**Attacker input**: The `block_hash` in `BlockReference::BlockId(BlockId::Hash(...))` is a public, unprivileged RPC parameter. No validator or operator privileges are needed.

---

### Title
Fork Block State Served as Canonical via `is_block_executed` Missing Canonicality Check — (`chain/chain/src/spice/chain.rs`)

### Summary
In Spice mode, `SpiceChainReader::is_block_executed` gates view queries solely on `DBCol::ChunkExtra` presence for the queried block hash, without verifying the block is on the canonical chain. Because `SpiceChunkExecutorActor` writes `ChunkExtra` for all executed blocks — including fork blocks — an unprivileged RPC caller can supply a non-canonical fork block hash via `BlockReference::BlockId(BlockId::Hash(...))` and receive a successful query response anchored to the fork block's state root, returning a wrong account balance or state value.

### Finding Description
`SpiceChainReader::is_block_executed` iterates tracked shards and returns `true` as soon as `get_chunk_extra(header.hash(), &shard_uid)` succeeds: [5](#0-4) 

There is no check that `header.hash()` corresponds to a block on the canonical chain. `ViewClientActor::get_block_header_by_reference` for `BlockId::Hash` retrieves the header from `DBCol::BlockHeader` (which stores all headers, canonical and fork), then calls `check_block_executed` as the sole gate: [2](#0-1) 

`handle_query` then fetches `ChunkExtra` by the fork block hash and passes its `state_root` to `runtime.query`: [6](#0-5) 

In Spice mode, `ChunkExtra` is written for fork blocks by `SpiceChunkExecutorActor`. The test `test_executing_forks` confirms fork blocks are executed and their `ChunkExtra` is present: [7](#0-6) 

### Impact Explanation
A client querying `ViewAccount`, `ViewState`, `ViewAccessKey`, or `CallFunction` with a fork block hash receives state from the fork's trie, not the canonical chain. The response includes the fork block hash and height, giving no indication the block is non-canonical. Clients (light clients, bridges, indexers) that receive block hashes from untrusted sources and validate state by querying by hash will receive wrong account balances or state values that appear verified.

### Likelihood Explanation
Requires knowing a fork block hash that was executed on the target node. Fork block hashes are observable by monitoring the p2p network or by querying `BlockHeadersRequest`. The window is before GC removes the fork block's data. In Spice mode, fork execution is the normal path, so the precondition is routinely met.

### Recommendation
Add a canonicality check in `get_block_header_by_reference` for the `BlockId::Hash` arm, analogous to `is_on_current_chain`: [8](#0-7) 

After retrieving the header by hash, verify `chain.get_block_header_by_height(header.height())?.hash() == block_hash`. If not, return `Error::DBNotFoundErr` (which `handle_query` maps to `QueryError::UnknownBlock`). Alternatively, extend `check_block_executed` to also assert canonicality for Spice blocks.

### Proof of Concept
In a test-loop with Spice enabled:
1. Produce `genesis → block_A → block_B` (canonical chain).
2. Produce `fork_block` off `genesis` (same height as `block_A`).
3. Execute `fork_block` via `SpiceChunkExecutorActor` — assert `block_executed(&actor, &fork_block)` is true.
4. Advance the canonical chain past `fork_block`'s height so it is abandoned.
5. Issue `Query { block_reference: BlockId::Hash(*fork_block.hash()), request: ViewAccount { account_id: ... } }`.
6. Assert the response returns `QueryError::UnknownBlock` — currently it returns `Ok(QueryResponse)` with state from the fork block's trie, not the canonical state.

### Citations

**File:** chain/chain/src/spice/chain.rs (L31-50)
```rust
    pub fn is_block_executed(&self, header: &BlockHeader) -> Result<bool, Error> {
        let epoch_id = header.epoch_id();
        let protocol_version = self.epoch_manager.get_epoch_protocol_version(epoch_id)?;
        if !ProtocolFeature::Spice.enabled(protocol_version) {
            return Ok(true);
        }
        let shard_ids = self.epoch_manager.shard_ids(epoch_id)?;
        for shard_id in shard_ids {
            if !self.shard_tracker.cares_about_shard(header.hash(), shard_id) {
                continue;
            }
            let shard_uid = shard_id_to_uid(self.epoch_manager.as_ref(), shard_id, epoch_id)?;
            match self.chain_store.chunk_store().get_chunk_extra(header.hash(), &shard_uid) {
                Ok(_) => return Ok(true),
                Err(Error::DBNotFoundErr(_)) => return Ok(false),
                Err(err) => return Err(err),
            }
        }
        Ok(false)
    }
```

**File:** chain/client/src/view_client_actor.rs (L250-254)
```rust
            BlockReference::BlockId(BlockId::Hash(block_hash)) => {
                let header = self.chain.get_block_header(block_hash)?;
                self.spice_chain_reader.check_block_executed(&header)?;
                Ok(Some(header))
            }
```

**File:** chain/client/src/view_client_actor.rs (L400-432)
```rust
        let chunk_extra =
            self.chain.get_chunk_extra(header.hash(), &shard_uid).map_err(|err| match err {
                near_chain::near_chain_primitives::Error::DBNotFoundErr(_) => {
                    // After ContinuousEpochSync is enabled, since block headers would be GC'd
                    // there'll be no way for us to tell whether a block hash is GC'd or just unknown.
                    if !ProtocolFeature::ContinuousEpochSync.enabled(PROTOCOL_VERSION)
                        && self.is_block_gc(header.height())
                    {
                        QueryError::GarbageCollectedBlock {
                            block_height: header.height(),
                            block_hash: *header.hash(),
                        }
                    } else {
                        QueryError::UnavailableShard { requested_shard_id: shard_id }
                    }
                }
                near_chain::near_chain_primitives::Error::IOErr(error) => {
                    QueryError::InternalError { error_message: error.to_string() }
                }
                _ => QueryError::Unreachable { error_message: err.to_string() },
            })?;

        let state_root = chunk_extra.state_root();
        match self.runtime.query(
            shard_uid,
            state_root,
            header.height(),
            header.raw_timestamp(),
            header.prev_hash(),
            header.hash(),
            header.epoch_id(),
            &msg.request,
        ) {
```

**File:** chain/client/src/spice/tests/chunk_executor_actor.rs (L687-697)
```rust
    let fork_block = produce_block(&mut actors, &blocks[0]);
    assert!(!block_executed(&actors[0], &blocks[1]));
    assert!(!block_executed(&actors[0], &fork_block));

    actors[0].handle_with_internal_events(ProcessedBlock { block_hash: *blocks[1].hash() });
    assert!(block_executed(&actors[0], &blocks[1]));
    assert!(!block_executed(&actors[0], &fork_block));

    actors[0].handle_with_internal_events(ProcessedBlock { block_hash: *fork_block.hash() });
    assert!(block_executed(&actors[0], &fork_block));
}
```

**File:** chain/chain/src/chain.rs (L1553-1560)
```rust
    /// Returns if given block header is on the current chain.
    ///
    /// This is done by fetching header by height and checking that it's the
    /// same one as provided.
    fn is_on_current_chain(&self, header: &BlockHeader) -> Result<bool, Error> {
        let chain_header = self.get_block_header_by_height(header.height())?;
        Ok(chain_header.hash() == header.hash())
    }
```
