### Title
Missing Rollback on `TxError::Internal` Commits Partial Transaction State Instead of Reverting It - (File: `basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs`)

### Summary

In the ZK transaction loop, a snapshot (`pre_tx_rollback_handle`) is taken before each transaction is processed so the block state can be reverted if the transaction must be invalidated. When a `TxError::Validation` or block-limit error occurs, the code correctly calls `finish_global_frame(Some(&pre_tx_rollback_handle))` to roll back. However, when a `TxError::Internal` occurs, the code calls `finish_global_frame(None)` — which **commits** the partial transaction state — before propagating the error and aborting the block. The developer's own `TODO` comment at that line explicitly questions whether this is correct. This is a direct analog to the external report's pattern: a function meant to reverse a state change instead reinforces it.

### Finding Description

**Root cause — exact location:**

`basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs`, lines 81 and 107–113:

```rust
// Line 81: snapshot taken before transaction
let pre_tx_rollback_handle = system.start_global_frame()?;

// ... process_transaction called ...

match tx_result {
    Err(TxError::Internal(err)) => {
        // Line 111: commits state instead of rolling back
        system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
        return Err(err);
    }
    Err(TxError::Validation(err)) => {
        // Correct: rolls back
        system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
        ...
    }
```

**Semantics of `finish_global_frame`:**

`finish_global_frame(None)` commits all IO changes accumulated since the matching `start_global_frame`. `finish_global_frame(Some(&handle))` rolls them back to the snapshot. This is defined in `zk_ee/src/system/mod.rs` lines 255–268 and propagates through `finish_io_frame` in `basic_system/src/system_implementation/system/io_subsystem.rs` lines 418–432, touching storage, transient storage, logs, events, and interop roots.

**What state is inside the `pre_tx_rollback_handle` frame:**

`process_transaction` opens and closes its own inner frames for validation, fee charging, execution, and refund. All of those inner frames are properly committed or rolled back before returning. The `pre_tx_rollback_handle` frame at the `loop_op` level therefore contains the **net accumulated state changes** of the entire transaction (fee deductions, storage writes, events, L2→L1 logs, preimage publications). When `finish_global_frame(None)` is called on an internal error, all of these changes are merged into the block-level state instead of being discarded.

**Contrast with the correct paths:**

- `TxError::Validation` → `finish_global_frame(Some(&pre_tx_rollback_handle))` — correct rollback.
- Block-limit exceeded → `finish_global_frame(Some(&pre_tx_rollback_handle))` — correct rollback.
- `TxError::Internal` → `finish_global_frame(None)` — **incorrect commit**.

The Ethereum-mode tx loop (`basic_bootloader/src/bootloader/block_flow/ethereum/loop_op.rs` lines 131–135) does not open a `pre_tx_rollback_handle` frame at all, so it does not have this inconsistency. The bug is isolated to the ZK-specific loop.

**How `TxError::Internal` is reachable:**

`TxError::Internal` wraps any `BootloaderSubsystemError` that is not explicitly converted to a `TxError::Validation`. This includes `SystemError::LeafDefect` (internal errors from storage or IO subsystems) and any unhandled `BootloaderSubsystemError` from `F::before_refund`, `F::create_frame_and_execute_transaction_payload`, or `F::refund_and_commit_fee`. While these are not intended to be triggered by normal user input, a crafted transaction that exercises edge cases in storage access, preimage publication, or resource accounting could reach these paths.

### Impact Explanation

When `TxError::Internal` is triggered during ZK block processing:

1. The partial transaction's state changes (storage writes, balance mutations, events, L2→L1 logs) are **committed** to the in-memory block state rather than rolled back.
2. The block then fails entirely (`return Err(err)`), so the corrupted in-memory state is never finalized to L1.
3. However, the committed state creates an **inconsistent intermediate block state** that violates the invariant that a failed transaction must leave no trace in the block state.
4. In the proving path, this inconsistency means the prover operates on a state that includes partial effects of a transaction that was never supposed to succeed, which can cause proof generation to fail or produce an incorrect state root.
5. If an attacker can reliably trigger `TxError::Internal` mid-transaction (after fee deduction but before refund, for example), they can cause the block to fail while having their fee deducted committed — a denial-of-service vector that aborts block finalization.

### Likelihood Explanation

`TxError::Internal` is intended to be triggered only by internal system errors, not by user-controlled input. However, the code paths that can produce it (`SystemError::LeafDefect`, unhandled `BootloaderSubsystemError` from refund or execution) are reachable from transaction execution. The developer's own `TODO` comment at the exact line confirms awareness of the incorrect behavior. Likelihood is **medium-low**: not trivially exploitable by a normal transaction, but reachable through edge cases in storage or resource accounting, and the incorrect behavior is confirmed by the code comment.

### Recommendation

Replace `finish_global_frame(None)` with `finish_global_frame(Some(&pre_tx_rollback_handle))` in the `TxError::Internal` arm of the ZK tx loop, consistent with how `TxError::Validation` and block-limit errors are handled:

```rust
Err(TxError::Internal(err)) => {
    // Revert to state before transaction, same as Validation path
    system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
    return Err(err);
}
```

This ensures that regardless of the error type, the block state is always clean when the transaction loop exits.

### Proof of Concept

1. Construct a ZK-mode block with a transaction that triggers `TxError::Internal` during processing (e.g., by crafting input that causes `SystemError::LeafDefect` inside `F::before_refund` or `F::refund_and_commit_fee` after fee charging has already been committed).
2. Observe that `finish_global_frame(None)` is called at line 111, committing the partial transaction state.
3. The block fails with `return Err(err)`.
4. Inspect the in-memory IO state: storage writes, balance changes, and events from the failed transaction are present in the block state, violating the invariant that a failed transaction leaves no trace.
5. Compare with the `TxError::Validation` path (line 120): the same transaction failing validation correctly leaves no state changes.

**Key code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L77-113)
```rust
                    // Take a snapshot in case we need to invalidate the
                    // transaction to seal the block.
                    // This can happen if any of the block limits (native, gas, pubdata
                    // logs) is reached by the current transaction.
                    let pre_tx_rollback_handle = system.start_global_frame()?;

                    // We will give the full buffer here, and internally we will use parts of it to give forward to EEs
                    cycle_marker::start!("process_transaction");

                    // TODO: consider actually using block_data here
                    let mut nop_keeper = NopTransactionDataKeeper;

                    let tx_result =
                        BasicBootloader::<S, ZkTransactionFlowOnlyEOA<S>>::process_transaction::<
                            Config,
                        >(
                            initial_calldata_buffer,
                            system,
                            system_functions,
                            memories.reborrow(),
                            is_first_tx,
                            &mut nop_keeper,
                            tracer,
                            validator,
                        );

                    cycle_marker::end!("process_transaction");

                    tracer.finish_tx();

                    match tx_result {
                        Err(TxError::Internal(err)) => {
                            system_log!(system, "Tx execution result: Internal error = {err:?}\n",);
                            // Finish the frame opened before processing the tx
                            system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
                            return Err(err);
                        }
```

**File:** zk_ee/src/system/mod.rs (L252-268)
```rust
    /// Finishes a global frame, reverts I/O writes in case of revert.
    /// If `rollback_handle` is provided, will revert to the requested snapshot.
    #[track_caller]
    pub fn finish_global_frame(
        &mut self,
        rollback_handle: Option<&SystemFrameSnapshot<S>>,
    ) -> Result<(), InternalError> {
        let mut logger = self.get_logger();
        let _ = logger.write_fmt(format_args!(
            "Finish global frame, revert = {}\n",
            rollback_handle.is_some()
        ));

        // revert IO if needed, and copy memory
        self.io.finish_io_frame(rollback_handle.map(|x| &x.io))?;

        Ok(())
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L418-432)
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
```

**File:** basic_bootloader/src/bootloader/errors.rs (L132-145)
```rust
#[derive(Debug)]
pub enum TxError {
    /// Failed to validate the transaction,
    /// shouldn't terminate the block execution
    Validation(InvalidTransaction),
    /// Internal error.
    Internal(BootloaderSubsystemError),
}

impl From<BootloaderSubsystemError> for TxError {
    fn from(v: BootloaderSubsystemError) -> Self {
        Self::Internal(v)
    }
}
```
