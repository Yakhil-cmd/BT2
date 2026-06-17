### Title
`NewSettlementLayerChainIdStorage` Not Linked to IO Frame Rollback Mechanism — (File: `basic_system/src/system_implementation/system/io_subsystem.rs`)

### Summary

`FullIO::start_io_frame` and `finish_io_frame` snapshot and roll back every sub-storage **except** `new_settlement_layer_chain_id_storage`. Because `NewSettlementLayerChainIdStorage` has its own `start_frame`/`finish_frame` methods that are never wired into the IO frame lifecycle, any update to the settlement-layer chain ID that occurs inside a reverted frame persists permanently in the block-level state. This is the direct analog of the reported pattern: a component that has rollback capability is never linked to the parent group that manages rollback.

---

### Finding Description

`FullIO` holds six sub-storages that must all be snapshotted and rolled back together when an execution frame reverts: [1](#0-0) 

The `FullIOStateSnapshot` captures five of them: [2](#0-1) 

`start_io_frame` takes a snapshot of every sub-storage **except** `new_settlement_layer_chain_id_storage`: [3](#0-2) 

`finish_io_frame` rolls back every sub-storage **except** `new_settlement_layer_chain_id_storage`: [4](#0-3) 

Yet `NewSettlementLayerChainIdStorage` already exposes `start_frame` / `finish_frame` backed by a `HistoryCounter`: [5](#0-4) 

These methods are simply never called from the IO frame path. By contrast, `interop_root_storage` — a structurally identical block-level list — **is** correctly wired into both `start_io_frame` and `finish_io_frame`.

The settlement-layer chain ID is written via `update_settlement_layer_chain_id`, which calls `self.new_settlement_layer_chain_id_storage.update(new_sl_chain_id)`: [6](#0-5) 

`update()` also enforces a once-per-block invariant — it returns an `InternalError` if called a second time: [7](#0-6) 

At block finalization, `read_batch_context_inputs` asserts that the value stored in `new_settlement_layer_chain_id_storage` matches the value actually committed to persistent storage: [8](#0-7) 

---

### Impact Explanation

Two concrete consequences follow from the missing rollback link:

**1. Block-finalization panic (state-transition divergence).** If a transaction that triggers `SettlementLayerChainIdUpdated` is subsequently reverted (e.g., the outer frame rolls back due to out-of-native resources or a block-limit check), the persistent storage slot for the chain ID is correctly restored to its old value, but `new_settlement_layer_chain_id_storage` still holds the new value. The assertion in `read_batch_context_inputs` then fires:

```
assert_eq!(new_settlement_layer_chain_id, &settlement_layer_chain_id);
```

This panics the prover/sequencer, making the block unprovable and breaking the state-transition function.

**2. Permanent DoS of the once-per-block update invariant.** Because `update()` rejects a second call with an internal error, a reverted update "consumes" the single allowed slot for the entire block. Any subsequent legitimate attempt to update the settlement-layer chain ID in the same block fails unconditionally, preventing the protocol from advancing the settlement-layer chain ID.

---

### Likelihood Explanation

The `system_context_event_hook` is registered as an event hook on `SYSTEM_CONTEXT_ADDRESS_LOW` and fires whenever the SystemContext contract emits `SettlementLayerChainIdUpdated`. A transaction that calls the SystemContext contract and is then reverted — whether due to out-of-native resources, a block-gas-limit check, or an explicit revert — is sufficient to trigger the inconsistency. The block-limit revert path is exercised in the normal transaction loop: [9](#0-8) 

Because native-resource exhaustion is reachable by any transaction sender (by crafting a transaction that consumes enough native resources to push the block over its limit), the entry path is externally reachable.

---

### Recommendation

Wire `new_settlement_layer_chain_id_storage` into the IO frame lifecycle, mirroring the existing treatment of `interop_root_storage`:

1. Add a `new_sl_chain_id: NewSettlementLayerChainIdSnapshotId` field to `FullIOStateSnapshot`.
2. In `start_io_frame`, call `self.new_settlement_layer_chain_id_storage.start_frame()` and store the result.
3. In `finish_io_frame`, call `self.new_settlement_layer_chain_id_storage.finish_frame(rollback_handle.map(|x| x.new_sl_chain_id))`.

---

### Proof of Concept

1. Block contains two transactions: **Tx A** (updates settlement-layer chain ID via SystemContext) and **Tx B** (any transaction that pushes the block over its native-resource limit, causing Tx A to be reverted by the block-limit check).
2. After Tx A is reverted, `new_settlement_layer_chain_id_storage` still holds the new chain ID, but the SystemContext storage slot holds the old value.
3. At block finalization, `read_batch_context_inputs` asserts `new_settlement_layer_chain_id == settlement_layer_chain_id` — the values differ, causing a panic and making the block unprovable.
4. Alternatively, if Tx A is reverted and a later Tx C in the same block legitimately tries to update the chain ID, `update()` returns `InternalError("Tried to update settlement layer chain id more than once in a block")`, permanently blocking the update for that block.

### Citations

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L39-59)
```rust
pub struct FullIO<
    A: Allocator + Clone + Default,
    R: Resources,
    P: StorageAccessPolicy<R, Bytes32>,
    SF: StackFactory<N>,
    const N: usize,
    O: IOOracle,
    M: StorageModel<IOTypes = EthereumIOTypesConfig, Resources = R, InitData = P, Allocator = A>,
    const PROOF_ENV: bool,
> {
    pub storage: M,
    pub transient_storage: GenericTransientStorage<WarmStorageKey, Bytes32, SF, N, A>,
    pub logs_storage: LogsStorage<SF, N, A>,
    pub events_storage: EventsStorage<MAX_EVENT_TOPICS, SF, N, A>,
    pub interop_root_storage: InteropRootStorage<SF, N, A>,
    pub new_settlement_layer_chain_id_storage: NewSettlementLayerChainIdStorage<SF, N, A>,
    pub allocator: A,
    pub oracle: O,
    pub tx_number: u32,
    pub da_commitment_scheme: Option<DACommitmentScheme>,
}
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L61-67)
```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
}
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L248-264)
```rust
    fn update_settlement_layer_chain_id(
        &mut self,
        _ee_type: ExecutionEnvironmentType,
        resources: &mut Self::Resources,
        new_sl_chain_id: U256,
    ) -> Result<(), SystemError> {
        // For native we charge just for the storage
        let native = <Self::Resources as Resources>::Native::from_computational(
            NEW_SL_CHAIN_ID_STORAGE_NATIVE_COST,
        );

        let to_charge = Self::Resources::from_native(native);
        resources.charge(&to_charge)?;

        self.new_settlement_layer_chain_id_storage
            .update(new_sl_chain_id)
    }
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L402-416)
```rust
    fn start_io_frame(&mut self) -> Result<Self::StateSnapshot, InternalError> {
        let io = self.storage.start_frame();
        let transient = self.transient_storage.start_frame();
        let messages = self.logs_storage.start_frame();
        let events = self.events_storage.start_frame();
        let interop_roots = self.interop_root_storage.start_frame();

        Ok(FullIOStateSnapshot {
            io,
            transient,
            messages,
            events,
            interop_roots,
        })
    }
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L418-433)
```rust
    fn finish_io_frame(
        &mut self,
        rollback_handle: Option<&Self::StateSnapshot>,
    ) -> Result<(), InternalError> {
        self.storage.finish_frame(rollback_handle.map(|x| &x.io))?;
        self.transient_storage
            .finish_frame(rollback_handle.map(|x| &x.transient))?;
        self.logs_storage
            .finish_frame(rollback_handle.map(|x| x.messages));
        self.events_storage
            .finish_frame(rollback_handle.map(|x| x.events));
        self.interop_root_storage
            .finish_frame(rollback_handle.map(|x| x.interop_roots));

        Ok(())
    }
```

**File:** zk_ee/src/common_structs/new_settlement_layer_chain_id_storage.rs (L37-62)
```rust
    pub fn start_frame(&mut self) -> NewSettlementLayerChainIdSnapshotId {
        self.history.snapshot()
    }

    pub fn update(&mut self, new_sl_chain_id: U256) -> Result<(), SystemError> {
        if self.value().is_some() {
            return Err(internal_error!(
                "Tried to update settlement layer chain id more than once in a block"
            )
            .into());
        }
        self.history.update(new_sl_chain_id);

        Ok(())
    }

    pub fn value(&self) -> Option<&U256> {
        self.history.value()
    }

    #[track_caller]
    pub fn finish_frame(&mut self, rollback_handle: Option<NewSettlementLayerChainIdSnapshotId>) {
        if let Some(x) = rollback_handle {
            self.history.rollback(x);
        }
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L231-241)
```rust
) -> (Bytes32, U256) {
    let multichain_root = read_multichain_root(io);
    let settlement_layer_chain_id = read_settlement_layer_chain_id(io);
    if let Some(new_settlement_layer_chain_id) = io.new_settlement_layer_chain_id_storage.value() {
        // If the SL chain id was updated, make sure the updated one matches
        // the one read from storage.
        assert_eq!(new_settlement_layer_chain_id, &settlement_layer_chain_id);
    }

    (multichain_root, settlement_layer_chain_id)
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L138-162)
```rust
                            // Do not update the accumulators yet, we may need to revert the transaction
                            let next_block_gas_used =
                                block_data.block_gas_used + tx_processing_result.gas_used;
                            let next_block_computational_native_used = block_data
                                .block_computational_native_used
                                + tx_processing_result.computational_native_used;
                            let next_block_pubdata_used =
                                block_data.block_pubdata_used + tx_processing_result.pubdata_used;
                            let block_logs_used = system.io.logs_len();
                            let next_block_blob_gas_used =
                                block_data.block_blob_gas_used + tx_processing_result.blob_gas_used;

                            // Check if the transaction made the block reach any of the limits
                            // for gas, native, pubdata or logs.
                            if let Err(err) = check_for_block_limits(
                                system,
                                next_block_gas_used,
                                next_block_computational_native_used,
                                next_block_pubdata_used,
                                block_logs_used,
                                next_block_blob_gas_used,
                            ) {
                                // Revert to state before transaction
                                system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                                result_keeper.tx_processed(Err(err));
```
