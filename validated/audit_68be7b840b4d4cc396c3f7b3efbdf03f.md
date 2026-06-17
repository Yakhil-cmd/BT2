### Title
Unchecked Return Value of `rollback` in `LogsStorage::finish_frame` and `EventsStorage::finish_frame` — (`zk_ee/src/common_structs/logs_storage.rs`, `zk_ee/src/common_structs/events_storage.rs`)

---

### Summary

`LogsStorage::finish_frame` and `EventsStorage::finish_frame` call `self.list.rollback(x)` without checking or propagating the return value. `finish_io_frame` — the top-level IO rollback path — then calls these methods without `?`, meaning a failed rollback of L2→L1 messages or EVM events is silently swallowed. The system proceeds as if the revert succeeded, leaving logs/events in an inconsistent state relative to storage.

---

### Finding Description

`finish_io_frame` in `FullIO` is the single entry point for reverting all IO state when a transaction or sub-frame is rolled back. [1](#0-0) 

The first two subsystems propagate errors correctly with `?`:

```rust
self.storage.finish_frame(rollback_handle.map(|x| &x.io))?;
self.transient_storage
    .finish_frame(rollback_handle.map(|x| &x.transient))?;
```

The remaining three do **not**:

```rust
self.logs_storage
    .finish_frame(rollback_handle.map(|x| x.messages));   // no ?
self.events_storage
    .finish_frame(rollback_handle.map(|x| x.events));     // no ?
self.interop_root_storage
    .finish_frame(rollback_handle.map(|x| x.interop_roots)); // no ?
```

This is possible because `LogsStorage::finish_frame` and `EventsStorage::finish_frame` are declared to return `()` rather than `Result<(), InternalError>`. The root cause is inside those implementations: they call `self.list.rollback(x)` and discard the return value entirely.

`LogsStorage::finish_frame`: [2](#0-1) 

```rust
pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
    if let Some(x) = rollback_handle {
        self.list.rollback(x);   // return value silently dropped
    }
}
```

`EventsStorage::finish_frame`: [3](#0-2) 

```rust
pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
    if let Some(x) = rollback_handle {
        self.list.rollback(x);   // return value silently dropped
    }
}
```

The analogous `HistoryMap::rollback` (used by storage) returns `Result<(), InternalError>` and is always propagated with `?`. [4](#0-3) 

The `SnapshottableIo` trait itself mandates `Result<(), InternalError>` for `finish_frame`, confirming that rollback operations are expected to be fallible: [5](#0-4) 

`LogsStorage` and `EventsStorage` bypass this contract by declaring their own `finish_frame` returning `()`, hiding any internal failure.

---

### Impact Explanation

When a transaction reverts (e.g., out-of-gas, EVM revert, block-limit exceeded), `finish_io_frame` is called with a non-`None` rollback handle. If the `HistoryList::rollback` inside `LogsStorage` or `EventsStorage` fails silently:

- **L2→L1 messages** emitted by the reverted transaction remain in `logs_storage` and are included in the block's pubdata output and L2→L1 log hash.
- **EVM events** from the reverted transaction remain in `events_storage` and are emitted in the block output.
- Storage and transient storage are correctly reverted (they use `?`), creating a split state: storage says the transaction reverted, but logs/events say it succeeded.
- This divergence corrupts the block's state commitment and L1 integration outputs, constituting a **state-transition bug** with direct impact on L2→L1 message integrity and event correctness.

---

### Likelihood Explanation

Every transaction revert path goes through `finish_io_frame` with a rollback handle: [6](#0-5) [7](#0-6) 

Any transaction that emits logs/events and then reverts exercises this path. The likelihood is **high** for any block containing reverting transactions that also emit L2→L1 messages or events before the revert point.

---

### Recommendation

1. Change `LogsStorage::finish_frame` and `EventsStorage::finish_frame` to return `Result<(), InternalError>` and propagate the inner `rollback` result:

```rust
pub fn finish_frame(&mut self, rollback_handle: Option<usize>) -> Result<(), InternalError> {
    if let Some(x) = rollback_handle {
        self.list.rollback(x)?;
    }
    Ok(())
}
```

2. Update `finish_io_frame` to propagate these errors with `?`:

```rust
self.logs_storage
    .finish_frame(rollback_handle.map(|x| x.messages))?;
self.events_storage
    .finish_frame(rollback_handle.map(|x| x.events))?;
self.interop_root_storage
    .finish_frame(rollback_handle.map(|x| x.interop_roots))?;
```

3. Align `LogsStorage` and `EventsStorage` with the `SnapshottableIo` trait contract, which already mandates `Result<(), InternalError>` for `finish_frame`.

---

### Proof of Concept

1. Deploy a contract that emits an L2→L1 message (calls `L1_MESSENGER`) and then reverts.
2. Submit a transaction calling that contract.
3. The transaction reverts; `finish_io_frame` is called with a rollback handle.
4. `logs_storage.finish_frame(Some(snapshot))` is called; if `self.list.rollback(snapshot)` returns an error, it is silently dropped.
5. `finish_io_frame` returns `Ok(())`.
6. The block finalizer iterates `logs_storage.iter_net_diff()` and includes the reverted L2→L1 message in pubdata and the L2→L1 log hash — corrupting the block's L1 commitment. [2](#0-1) [3](#0-2) [8](#0-7)

### Citations

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

**File:** zk_ee/src/common_structs/logs_storage.rs (L243-247)
```rust
    pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
        if let Some(x) = rollback_handle {
            self.list.rollback(x);
        }
    }
```

**File:** zk_ee/src/common_structs/events_storage.rs (L103-108)
```rust
    #[track_caller]
    pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
        if let Some(x) = rollback_handle {
            self.list.rollback(x);
        }
    }
```

**File:** zk_ee/src/common_structs/history_map/mod.rs (L143-156)
```rust
    #[must_use]
    /// Rollbacks the data to the state at the provided `snapshot_id`.
    pub fn rollback(&mut self, snapshot_id: CacheSnapshotId) -> Result<(), InternalError> {
        if snapshot_id < self.state.frozen_snapshot_id {
            return Err(internal_error!(
                "History map: rollback below frozen snapshot"
            ));
        }

        if snapshot_id >= self.state.next_snapshot_id {
            return Err(internal_error!(
                "History map: rollback to non-existent snapshot"
            ));
        }
```

**File:** storage_models/src/common_structs/traits/snapshottable_io.rs (L11-14)
```rust
    fn finish_frame(
        &mut self,
        rollback_handle: Option<&Self::StateSnapshot>,
    ) -> Result<(), InternalError>;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L119-122)
```rust
                            // Revert to state before transaction
                            system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                            result_keeper.tx_processed(Err(err));
                        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L205-208)
```rust
                    } else {
                        system.finish_global_frame(Some(&rollback_handle))?;
                        None
                    };
```
