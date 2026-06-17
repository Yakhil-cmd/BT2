### Title
`new_settlement_layer_chain_id_storage` Omitted from Frame Snapshot Causes Irreversible State Mutation on Revert — (`basic_system/src/system_implementation/system/io_subsystem.rs`)

---

### Summary

`FullIO` contains six sub-storages, but `FullIOStateSnapshot` only captures five of them. `new_settlement_layer_chain_id_storage` is never snapshotted in `start_io_frame` and never rolled back in `finish_io_frame`. Any write to this storage inside a frame that subsequently reverts will permanently persist, violating the atomicity guarantee of the frame/rollback mechanism — directly analogous to the Velodrome bug where a missing index caused a state flag to always read as its zero/default value instead of the correct prior value.

---

### Finding Description

`FullIO` declares six sub-storages: [1](#0-0) 

```rust
pub struct FullIO<...> {
    pub storage: M,
    pub transient_storage: ...,
    pub logs_storage: ...,
    pub events_storage: ...,
    pub interop_root_storage: ...,
    pub new_settlement_layer_chain_id_storage: NewSettlementLayerChainIdStorage<SF, N, A>,
    ...
}
```

But `FullIOStateSnapshot` only captures five: [2](#0-1) 

```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
    // new_settlement_layer_chain_id_storage is ABSENT
}
```

`start_io_frame` snapshots `storage`, `transient_storage`, `logs_storage`, `events_storage`, and `interop_root_storage`, but never calls `start_frame` on `new_settlement_layer_chain_id_storage`: [3](#0-2) 

`finish_io_frame` rolls back the same five storages and silently skips `new_settlement_layer_chain_id_storage`: [4](#0-3) 

The structural parallel to the Velodrome bug is exact: just as `checkpoints[account][_nCheckPoints]` (an uninitialized mapping slot, always returning the zero default) was read instead of `checkpoints[account][_nCheckPoints - 1]` (the actual previous checkpoint), here the snapshot struct is missing a field entirely — the effect in both cases is that the relevant state is always left at its "empty/default" value after the operation, rather than being correctly restored to its prior value.

`NewSettlementLayerChainIdStorage` uses a `HistoryList` with `snapshot()` / `rollback()` methods (same pattern as `InteropRootStorage`), so the fix is straightforward — the infrastructure already exists, it is simply not wired up. [5](#0-4) 

---

### Impact Explanation

Any call path that writes to `new_settlement_layer_chain_id_storage` (via `update_settlement_layer_chain_id`) inside a frame that later reverts will leave the storage permanently mutated. The settlement layer chain ID governs cross-chain interoperability and security verification. A spurious or attacker-induced write that survives a revert could corrupt the chain's cross-chain state, potentially causing invalid cross-chain messages to be accepted or valid ones to be rejected — a state-transition correctness violation with direct protocol-level impact.

---

### Likelihood Explanation

`update_settlement_layer_chain_id` is exposed through the `IOSubsystem` trait and is dispatched from system hooks. System hooks are invoked when EVM execution calls specific system addresses (e.g., `0x8003` for account properties). If a user-controlled EVM `CALL` can reach a system hook that internally invokes `update_settlement_layer_chain_id`, and the outer frame reverts (out-of-gas, explicit `REVERT`, or a failed sub-call), the chain ID write persists. The likelihood is moderate: it requires a code path through a system hook, but system hooks are reachable from ordinary EVM `CALL` instructions to system addresses. The missing rollback is unconditional — it fires on every revert regardless of how the frame was entered.

---

### Recommendation

Add `new_settlement_layer_chain_id_storage` to `FullIOStateSnapshot` and wire it into both `start_io_frame` and `finish_io_frame`, mirroring the existing pattern for `interop_root_storage`:

```rust
pub struct FullIOStateSnapshot<M: StorageModel> {
    io: M::StateSnapshot,
    transient: CacheSnapshotId,
    messages: usize,
    events: usize,
    interop_roots: usize,
    new_sl_chain_ids: usize,  // add
}
```

```rust
fn start_io_frame(&mut self) -> Result<Self::StateSnapshot, InternalError> {
    // ... existing snapshots ...
    let new_sl_chain_ids = self.new_settlement_layer_chain_id_storage.start_frame();
    Ok(FullIOStateSnapshot { ..., new_sl_chain_ids })
}

fn finish_io_frame(&mut self, rollback_handle: Option<&Self::StateSnapshot>) -> Result<(), InternalError> {
    // ... existing rollbacks ...
    self.new_settlement_layer_chain_id_storage
        .finish_frame(rollback_handle.map(|x| x.new_sl_chain_ids));
    Ok(())
}
```

---

### Proof of Concept

1. User sends a transaction that calls a system hook address which internally invokes `update_settlement_layer_chain_id` with a new chain ID value.
2. The system hook call succeeds, writing to `new_settlement_layer_chain_id_storage`.
3. The outer frame reverts (e.g., the transaction runs out of gas or explicitly reverts after the system hook call returns).
4. `finish_io_frame` is called with a rollback handle. All five tracked storages are rolled back, but `new_settlement_layer_chain_id_storage` is not touched.
5. The new settlement layer chain ID persists in the state despite the transaction having reverted, violating the atomicity invariant of the frame mechanism.

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

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L36-52)
```rust
    #[track_caller]
    pub fn start_frame(&mut self) -> usize {
        self.list.snapshot()
    }

    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
    }

    #[track_caller]
    pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
        if let Some(x) = rollback_handle {
            self.list.rollback(x);
        }
    }
```
