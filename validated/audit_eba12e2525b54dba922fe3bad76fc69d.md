### Title
Multi-Block Batch L2→L1 Log Accumulator Overflow Causes Batch Proof Panic, Blocking Message Finalization - (`basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

In the multi-block batch proving path, L2→L1 log hashes from each block are accumulated into a fixed-capacity `ArrayVec<Bytes32, 16384>` inside `ZKBatchDataKeeper`. The per-block log limit is also 16,384. Because the accumulator is sized for exactly one block's worth of logs but is used across all blocks in a batch, any multi-block batch whose total log count exceeds 16,384 will cause an unconditional panic inside `apply_to_array_vec`, making it impossible to generate the batch proof. This permanently blocks finalization of those blocks on L1 and prevents all L2→L1 messages in the affected batch from ever being claimed.

---

### Finding Description

**Root cause — accumulator capacity equals per-block limit:**

`ZKBatchDataKeeper.logs_storage` is declared as:

```rust
pub logs_storage: ArrayVec<Bytes32, 16384>,
``` [1](#0-0) 

The per-block log limit enforced in `check_for_block_limits` is:

```rust
} else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
    Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
}
``` [2](#0-1) 

where `MAX_NUMBER_OF_LOGS = 16_384`: [3](#0-2) 

The check is `> 16_384`, so a block with exactly 16,384 logs passes validation. In the multi-block batch proving post-op, each block's logs are pushed into the shared accumulator:

```rust
io.logs_storage
    .apply_to_array_vec(&mut batch_data.logs_storage);
``` [4](#0-3) 

`apply_to_array_vec` calls `ArrayVec::push` for every log:

```rust
pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
    self.list.iter().for_each(|el| {
        let log: L2ToL1Log = el.into();
        array_vec.push(log.hash())   // panics when capacity is exceeded
    });
}
``` [5](#0-4) 

`ArrayVec::push` panics unconditionally when the array is full. There is no bounds check before the call, and no per-batch total log limit anywhere in the code. A batch containing Block A (16,384 logs) followed by Block B (≥ 1 log) will panic during the RISC-V proving run when Block B's logs are pushed.

The `l2_logs_root` function that consumes the accumulator is only reached after all blocks have been accumulated: [6](#0-5) 

---

### Impact Explanation

When the panic occurs during the RISC-V proving run, the batch proof cannot be produced. In a ZK rollup, no proof means no L1 state transition. Concretely:

- All L2→L1 messages (user messages and L1→L2 tx result logs) in the affected batch can never be finalized or claimed on L1.
- The rollup's L1 state pointer cannot advance past the affected batch, effectively halting the chain's settlement layer progress until the operator manually restructures the batch (if possible).

This is a direct analog to the Linea bug: an incorrect/unconstrained tree parameter causes message claiming to become permanently impossible.

---

### Likelihood Explanation

**Attacker-controlled entry path:**

1. An unprivileged user calls the L1 Messenger system hook (`sendToL1`) repeatedly within a single block, or submits 16,384 L1→L2 priority transactions on L1 (each generates one L2→L1 result log). Either path fills the per-block log capacity of 16,384.
2. The operator, following normal sequencing rules, includes these transactions in Block A.
3. Any subsequent Block B in the same multi-block batch that contains even a single L2→L1 log (e.g., one L1→L2 tx result) triggers the panic.

The cost is the gas required to emit 16,384 L2→L1 logs in one block. This is non-trivial but achievable by a motivated attacker. L1→L2 priority transactions are particularly attractive because the operator is obligated to include them, and the attacker pays L1 gas rather than L2 gas.

The `resources_for_tester` feature flag that bypasses the per-block log limit is not set in production, so the 16,384 cap is enforced — but it is exactly equal to the accumulator capacity, leaving zero margin.

---

### Recommendation

1. **Enforce a per-batch total log limit** before calling `apply_to_array_vec`, rejecting or splitting batches that would exceed the accumulator capacity.
2. **Replace the panic with a graceful error**: use `ArrayVec::try_push` (or check `remaining_capacity()` before pushing) and propagate an error instead of panicking.
3. **Size the accumulator for the actual maximum batch size**: if a batch can contain N blocks each with up to 16,384 logs, the accumulator must have capacity `N × 16,384`, or the batch must be split when the limit is approached.

---

### Proof of Concept

```
Block A: 16,384 L2→L1 logs (attacker fills block via sendToL1 or L1→L2 txs)
  → passes check_for_block_limits (logs_used == 16_384, not > 16_384)
  → apply_to_array_vec fills logs_storage to capacity 16_384/16_384

Block B: 1 L2→L1 log (any normal transaction with an L1→L2 result log)
  → apply_to_array_vec calls array_vec.push(...)
  → ArrayVec is already at capacity → PANIC

Batch proof generation aborts.
l2_logs_root is never computed.
BatchPublicInput is never produced.
L1 state transition never submitted.
All L2→L1 messages in the batch are permanently unclaimable.
``` [1](#0-0) [5](#0-4) [4](#0-3) [2](#0-1)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L27-27)
```rust
    pub logs_storage: ArrayVec<Bytes32, 16384>,
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L126-128)
```rust
        chain_batch_root_hasher.update(Self::l2_logs_root(self.logs_storage).as_u8_ref());
        chain_batch_root_hasher.update(self.multichain_root.as_u8_ref());
        let chain_batch_root = chain_batch_root_hasher.finalize();
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L109-110)
```rust
        io.logs_storage
            .apply_to_array_vec(&mut batch_data.logs_storage);
```
