### Title
Hardcoded `ArrayVec<Bytes32, 16384>` Capacity in `ZKBatchDataKeeper` Causes Prover Panic on Multiblock Batch Overflow — (`File: basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

`ZKBatchDataKeeper::logs_storage` is typed as `ArrayVec<Bytes32, 16384>`, a fixed-capacity array that accumulates L2→L1 log hashes across **all blocks** in a multiblock batch. The per-block log limit (`MAX_NUMBER_OF_LOGS = 16_384`) is enforced per-block, but no per-batch limit exists. When a batch spans multiple blocks whose combined log count exceeds 16 384, `apply_to_array_vec` panics unconditionally, making the batch unprovable.

---

### Finding Description

**Root cause — hardcoded capacity mismatch:**

`ZKBatchDataKeeper` declares its log accumulator as:

```rust
logs_storage: ArrayVec<Bytes32, 16384>
```

<cite repo="Jaredbentat/zksync-os--014" path="basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs" start="178" end