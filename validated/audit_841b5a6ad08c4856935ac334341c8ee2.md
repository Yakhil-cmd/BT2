### Title
`new_settlement_layer_chain_id_storage` Excluded from IO Frame Snapshot Causes Unrollbackable State Desynchronization - (`basic_system/src/system_implementation/system/io_subsystem.rs`)

### Summary

`FullIOStateSnapshot` omits the `new_settlement_layer_chain_id_storage` sub-storage from its snapshot fields. As a result, `start_io_frame()` never takes a snapshot of it and `finish_io_frame()` never rolls it back on revert. If any execution frame that calls `update_settlement_layer_chain_id()` is subsequently reverted (e.g., due to block-limit overflow, out-of-native, or explicit EVM revert), the `new_settlement_layer_chain_id_storage` retains the written value while the underlying persistent storage slot is rolled back. This creates an irreconcilable divergence that causes block finalization to panic and the block to become unprovable.

### Finding Description

`FullIO` holds six sub-storages that must all be snapshotted and rolled back together to maintain consistency:

```
storage                              (M)
transient_storage                    (GenericTransientStorage)
logs_storage                         (LogsStorage)
events_storage                       (EventsStorage)
interop_root_storage                 (InteropRootStorage)
new_settlement_layer_chain_id_storage (NewSettlementLayerChainIdStorage)  ← MISSING
```

`FullIOStateSnapshot` only captures five of them: [1](#0-0) 

`start_io_frame()` calls `start_frame()` on five sub-storages but never on `new_settlement_layer_chain_id_storage`: [2](#0-1) 

`finish_io_frame()` rolls back five sub-storages but never calls `new_settlement_layer_chain_id_storage.finish_frame()`: [3](#0-2) 

`new_settlement_layer_chain_id_storage` does implement `start_frame()` / `finish_frame()` with full rollback capability via `HistoryCounter`: [4](#0-3) 

The value is written by `update_settlement_layer_chain_id()`, which is called from the `system_context_event_hook` whenever the SystemContext contract emits a `SettlementLayerChainIdUpdated` event: [5](#0-4) [6](#0-5) 

At block finalization, `read_batch_context_inputs` asserts that the value in `new_settlement_layer_chain_id_storage` matches the SL chain ID read from persistent storage: [7](#0-6) 

If the frame that wrote to `new_settlement_layer_chain_id_storage` was reverted, the persistent storage slot is rolled back to the old value, but `new_settlement_layer_chain_id_storage` still holds the new value. The `assert_eq!` panics, making the block unfinalizeable and unprovable.

A secondary impact: `update()` enforces a "write-once per block" invariant: [8](#0-7) 

If the first write was in a reverted frame, the storage still reports `value().is_some()`, so any subsequent legitimate update attempt returns an `InternalError`, which propagates as a fatal error and halts block processing entirely.

### Impact Explanation

A block that contains a reverted `setSettlementLayerChainId` service transaction will:

1. Fail the `assert_eq!` in `read_batch_context_inputs` during block finalization, causing a panic in both the forward (sequencer) and proving paths.
2. Alternatively, if a second legitimate update is attempted after the reverted one, the "write-once" guard fires an `InternalError`, halting the block.

Either outcome makes the block unprovable and breaks the state-transition function. In a multiblock-batch scenario, the `ZKBatchDataKeeper` accumulates the incorrect `settlement_layer_chain_id` into the batch public input, corrupting the on-chain commitment. [9](#0-8) 

### Likelihood Explanation

The trigger path is:

1. A transaction (service or user-initiated, depending on SystemContext access controls) causes the SystemContext contract to emit `SettlementLayerChainIdUpdated`.
2. The event hook fires, writing to `new_settlement_layer_chain_id_storage`.
3. The frame is subsequently reverted — via block-limit overflow (gas, native, pubdata, or log count), out-of-native, or explicit EVM revert.

The ZK tx loop explicitly reverts transactions that exceed block limits: [10](#0-9) 

A user who fills the block with gas/pubdata before the service transaction runs can force the service transaction to be reverted by block-limit overflow, triggering the bug without any privileged access. The `new_settlement_layer_chain_id_storage` is also not reset between transactions (`begin_next_tx` does not call it): [11](#0-10) 

### Recommendation

Add `new_settlement_layer_chain_id_storage` to `FullIOStateSnapshot` and wire it into `start_io_frame()` / `finish_io_frame()`, mirroring the existing pattern for `interop_root_storage`:

```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
+   new_sl_chain_id: NewSettlementLayerChainIdSnapshotId,
}

fn start_io_frame(&mut self) -> Result<Self::StateSnapshot, InternalError> {
    let io = self.storage.start_frame();
    let transient = self.transient_storage.start_frame();
    let messages = self.logs_storage.start_frame();
    let events = self.events_storage.start_frame();
    let interop_roots = self.interop_root_storage.start_frame();
+   let new_sl_chain_id = self.new_settlement_layer_chain_id_storage.start_frame();
    Ok(FullIOStateSnapshot { io, transient, messages, events, interop_roots, new_sl_chain_id })
}

fn finish_io_frame(&mut self, rollback_handle: Option<&Self::StateSnapshot>) -> Result<(), InternalError> {
    self.storage.finish_frame(rollback_handle.map(|x| &x.io))?;
    self.transient_storage.finish_frame(rollback_handle.map(|x| &x.transient))?;
    self.logs_storage.finish_frame(rollback_handle.map(|x| x.messages));
    self.events_storage.finish_frame(rollback_handle.map(|x| x.events));
    self.interop_root_storage.finish_frame(rollback_handle.map(|x| x.interop_roots));
+   self.new_settlement_layer_chain_id_storage.finish_frame(rollback_handle.map(|x| x.new_sl_chain_id));
    Ok(())
}
```

### Proof of Concept

1. Block contains two transactions in order: `[user_tx_fill_block, service_tx_set_sl_chain_id(42)]`.
2. `user_tx_fill_block` consumes gas/pubdata up to just below the block limit.
3. `service_tx_set_sl_chain_id(42)` begins execution:
   - `start_global_frame()` → `start_io_frame()` snapshots 5 sub-storages, **not** `new_settlement_layer_chain_id_storage`.
   - SystemContext emits `SettlementLayerChainIdUpdated(42)`.
   - Event hook fires: `new_settlement_layer_chain_id_storage.update(42)` — value is now `Some(42)`.
   - Persistent storage slot for SL chain ID is written to `42`.
4. Block-limit check fires (pubdata overflow). `finish_global_frame(Some(&rollback_handle))` is called:
   - `finish_io_frame(Some(...))` rolls back persistent storage (SL chain ID slot → old value), transient, logs, events, interop roots.
   - `new_settlement_layer_chain_id_storage` is **not** rolled back — still holds `Some(42)`.
5. Block finalization calls `read_batch_context_inputs`:
   - `read_settlement_layer_chain_id(io)` reads the persistent slot → old value (e.g., `1`).
   - `io.new_settlement_layer_chain_id_storage.value()` → `Some(42)`.
   - `assert_eq!(42, 1)` → **panic** → block is unfinalizeable and unprovable.

### Citations

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

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L523-528)
```rust
    fn begin_next_tx(&mut self) {
        self.storage.begin_new_tx();
        self.transient_storage.begin_new_tx();
        self.logs_storage.begin_new_tx();
        self.events_storage.begin_new_tx();
    }
```

**File:** zk_ee/src/common_structs/new_settlement_layer_chain_id_storage.rs (L36-62)
```rust
    #[track_caller]
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

**File:** system_hooks/src/event_hooks/system_context.rs (L60-65)
```rust
    let new_sl_chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    system.io.update_settlement_layer_chain_id(
        ExecutionEnvironmentType::NoEE,
        resources,
        new_sl_chain_id,
    )?;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L232-238)
```rust
    let multichain_root = read_multichain_root(io);
    let settlement_layer_chain_id = read_settlement_layer_chain_id(io);
    if let Some(new_settlement_layer_chain_id) = io.new_settlement_layer_chain_id_storage.value() {
        // If the SL chain id was updated, make sure the updated one matches
        // the one read from storage.
        assert_eq!(new_settlement_layer_chain_id, &settlement_layer_chain_id);
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L82-96)
```rust
            self.settlement_layer_chain_id = Some(settlement_layer_chain_id);
            self.is_first_block = false;
        } else {
            assert_eq!(
                self.current_state_commitment.unwrap(),
                state_commitment_before
            );
            self.current_state_commitment = Some(state_commitment_after);
            self.current_block_timestamp = Some(block_timestamp);
            assert_eq!(self.chain_id.unwrap(), chain_id);
            assert!(upgrade_tx_hash.is_zero());
            assert_eq!(
                self.settlement_layer_chain_id,
                Some(settlement_layer_chain_id)
            );
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L152-162)
```rust
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
