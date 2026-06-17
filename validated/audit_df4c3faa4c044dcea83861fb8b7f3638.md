### Title
Multi-Block Batch Prover Panic via Fixed-Capacity `logs_storage` Overflow in `ZKBatchDataKeeper` — (`basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

`ZKBatchDataKeeper` accumulates L2→L1 log hashes across all blocks in a multi-block batch into a fixed-capacity `ArrayVec<Bytes32, 16384>`. The per-block log limit is also 16,384. When a first block in a batch reaches the per-block log limit and a second block in the same batch emits even one log, `apply_to_array_vec` calls `ArrayVec::push` on a full array, causing an unconditional panic in the prover. This permanently halts proof generation for that batch.

---

### Finding Description

`ZKBatchDataKeeper` declares its batch-level log accumulator as:

```rust
pub logs_storage: ArrayVec<Bytes32, 16384>,
``` [1](#0-0) 

The per-block log limit is defined as:

```rust
pub const MAX_NUMBER_OF_LOGS: u64 = 16_384;
``` [2](#0-1) 

This limit is enforced per-block in `check_for_block_limits`:

```rust
} else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
    Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
``` [3](#0-2) 

At the end of each block in the multi-block proving path, all per-block logs are appended to the batch accumulator:

```rust
io.logs_storage
    .apply_to_array_vec(&mut batch_data.logs_storage);
``` [4](#0-3) 

`apply_to_array_vec` uses `ArrayVec::push` (not `try_push`):

```rust
pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
    self.list.iter().for_each(|el| {
        let log: L2ToL1Log = el.into();
        array_vec.push(log.hash())   // panics unconditionally when full
    });
}
``` [5](#0-4) 

`arrayvec::ArrayVec::push` panics when the vector is at capacity. There is **no bounds check** before appending, and **no batch-level log total limit** enforced anywhere. The per-block limit (16,384) equals the batch accumulator capacity (16,384), so a batch with two blocks each having any logs can overflow the accumulator if the first block is at the per-block maximum.

---

### Impact Explanation

When the prover processes a multi-block batch where block 1 contains 16,384 logs and block 2 contains ≥1 log, `apply_to_array_vec` panics inside the RISC-V proving binary. A panic in the prover causes the entire batch proof to fail. The batch is committed on-chain but can never be proven, permanently stalling the L1 state finalization for that batch and all subsequent batches that depend on it. This is a **permanent proving DoS** triggered by an unprivileged transaction sender.

---

### Likelihood Explanation

Every L1→L2 (priority) transaction automatically emits one L2→L1 log via `emit_l1_l2_tx_log`:

```rust
if is_priority_op {
    system.io.emit_l1_l2_tx_log(
        ExecutionEnvironmentType::NoEE,
        &mut inf_resources,
        tx_hash,
        is_success,
    )?;
}
``` [6](#0-5) 

User messages via `sendToL1` (the L1 messenger hook) also emit logs:

```rust
system.io.emit_l1_message(
    ExecutionEnvironmentType::NoEE,
    resources,
    &address_sender,
    message,
)?;
``` [7](#0-6) 

An attacker can fill a block with 16,384 L1→L2 transactions (each emitting one log) to saturate the per-block limit, then ensure the next block in the same multi-block batch contains at least one log (trivially achieved by any L1→L2 transaction or `sendToL1` call). The cost is bounded by 16,384 × (minimum L1→L2 transaction fee), which is low relative to the impact.

---

### Recommendation

1. **Replace `ArrayVec::push` with `try_push`** in `apply_to_array_vec` and propagate the error, so overflow is caught gracefully rather than panicking.

2. **Enforce a batch-level log total limit** in the multi-block batch post-tx-op path, rejecting or sealing a batch before `logs_storage` can overflow.

3. **Resize the batch accumulator** to `MAX_NUMBER_OF_LOGS * MAX_BLOCKS_PER_BATCH` or use a dynamically-sized `Vec` (as `tree_root()` already does for the single-block path) instead of a fixed-capacity `ArrayVec`.

---

### Proof of Concept

1. Attacker submits 16,384 L1→L2 priority transactions in a single block. Each transaction emits one L2→L1 log. The block-level check `logs_used > MAX_NUMBER_OF_LOGS` (16,384) allows exactly 16,384 logs, so the block is accepted.

2. The sequencer seals block 1 and starts block 2 in the same multi-block batch. Any single L1→L2 transaction or `sendToL1` call in block 2 emits one log.

3. During proving of the multi-block batch, `apply_to_array_vec` is called for block 1 (fills `logs_storage` to capacity 16,384), then called again for block 2. The first `push` in the second call invokes `ArrayVec::push` on a full array.

4. `arrayvec::ArrayVec::push` panics. The RISC-V prover binary aborts. The batch cannot be proven. L1 state finalization is permanently stalled for this batch.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L27-27)
```rust
    pub logs_storage: ArrayVec<Bytes32, 16384>,
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L25-25)
```rust
pub const MAX_NUMBER_OF_LOGS: u64 = 16_384;
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L311-315)
```rust
    pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
        self.list.iter().for_each(|el| {
            let log: L2ToL1Log = el.into();
            array_vec.push(log.hash())
        });
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L84-90)
```rust
    } else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block logs limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L109-110)
```rust
        io.logs_storage
            .apply_to_array_vec(&mut batch_data.logs_storage);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L364-371)
```rust
    if is_priority_op {
        system.io.emit_l1_l2_tx_log(
            ExecutionEnvironmentType::NoEE,
            &mut inf_resources,
            tx_hash,
            is_success,
        )?;
    }
```

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L155-161)
```rust
    system.io.emit_l1_message(
        // Gas should be charged by the L1Messenger system contract
        ExecutionEnvironmentType::NoEE,
        resources,
        &address_sender,
        message,
    )?;
```
