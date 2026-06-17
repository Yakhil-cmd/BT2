The code evidence is conclusive. Here is the analysis:

---

**Key facts established from the code:**

1. `MAX_NUMBER_OF_LOGS = 16_384` — the per-block limit uses a **strict** `>` check, so exactly 16,384 logs per block is **allowed**. [1](#0-0) [2](#0-1) 

2. `ZKBatchDataKeeper.logs_storage` is `ArrayVec<Bytes32, 16384>` — a fixed-capacity array that **accumulates logs from all blocks** in a multiblock batch. [3](#0-2) 

3. In the multiblock proving path, `apply_to_array_vec` is called once per block, appending that block's logs into the shared batch-level `ArrayVec`. [4](#0-3) 

4. `apply_to_array_vec` uses `array_vec.push(log.hash())` — `ArrayVec::push` **panics** (does not return `Result`) when the vec is at capacity. [5](#0-4) 

---

**The vulnerability:**

There is **no batch-level log count guard**. The per-block limit allows up to 16,384 logs per block, but the batch-level `ArrayVec` has the same fixed capacity of 16,384 total. Any multiblock batch where the cumulative log count across blocks exceeds 16,384 will panic the prover.

**Concrete scenario (no single-block pubdata overflow needed):**
- Block 1: 10,000 logs (within per-block pubdata and log limits)
- Block 2: 6,385 logs (within per-block pubdata and log limits)
- Cumulative: 16,385 → `apply_to_array_vec` panics on the 16,385th `push`

The pubdata limit prevents a single block from reaching 16,384 logs (16,384 × 92 bytes minimum ≈ 1.5 MB, exceeding the ~1.14 MB blob capacity), but it does **not** prevent the cumulative total across blocks from exceeding 16,384. The pubdata limit is per-block, not per-batch. [6](#0-5) 

The `new_for_test` configuration sets `pubdata_limit: u64::MAX`, confirming the limit is operator-supplied and variable. [7](#0-6) 

---

### Title
Multiblock Batch Prover Panic via ArrayVec Overflow from Cross-Block Log Accumulation — (`basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`, `zk_ee/src/common_structs/logs_storage.rs`)

### Summary
The `ZKBatchDataKeeper.logs_storage` field is an `ArrayVec<Bytes32, 16384>` that accumulates L2→L1 log hashes from every block in a multiblock batch. The per-block limit allows up to 16,384 logs per block (strict `>` check), but there is no batch-level guard. When the cumulative log count across blocks exceeds 16,384, `apply_to_array_vec` calls `ArrayVec::push` on a full array, causing an unconditional Rust panic that halts the prover and makes the batch unprovable.

### Finding Description
In `post_tx_op_proving_multiblock_batch.rs` line 109–110, after each block is processed, its logs are appended to `batch_data.logs_storage` via `apply_to_array_vec`. This function iterates all logs and calls `array_vec.push(log.hash())` with no capacity check. `ArrayVec::push` panics on overflow. The batch-level `ArrayVec` has capacity 16,384 — identical to the per-block maximum — so any multiblock batch whose blocks collectively emit more than 16,384 logs triggers the panic.

The per-block check `logs_used > MAX_NUMBER_OF_LOGS` uses strict greater-than, permitting exactly 16,384 logs in a single block. Even if pubdata constraints prevent a single block from reaching that maximum, two blocks each emitting ~8,193 logs (well within pubdata limits) will overflow the batch accumulator.

### Impact Explanation
The prover panics with an unrecoverable abort. The multiblock batch cannot be finalized, and no public input is produced. L1 settlement halts for the affected batch. An attacker who can cause this condition can permanently stall batch proving until the operator intervenes (e.g., by splitting the batch differently), constituting a sustained DoS on L1 finality.

### Likelihood Explanation
Any L2 user can emit L1 messages via the L1Messenger system hook. Generating ~8,000–10,000 messages across two blocks is feasible within gas and pubdata limits. The multiblock batch feature is a production build target (`production,multiblock-batch` feature flags). No privileged access is required.

### Recommendation
Add a batch-level log count check before calling `apply_to_array_vec`, returning an error if `batch_data.logs_storage.len() + block_logs_count > 16384`. Alternatively, replace `push` with `try_push` in `apply_to_array_vec` and propagate the error. Also fix the off-by-one in the per-block check: use `>= MAX_NUMBER_OF_LOGS` (i.e., allow at most 16,383 logs per block) to ensure a single block can never fill the batch accumulator alone.

### Proof of Concept
```
1. Deploy a contract on L2 that calls L1Messenger.sendToL1() in a loop.
2. Submit transactions in Block 1 that collectively emit 10,000 L1 messages.
   - Each passes check_for_block_limits (10,000 < 16,384 logs, pubdata within limit).
3. Submit transactions in Block 2 that collectively emit 6,385 L1 messages.
   - Each passes check_for_block_limits individually.
4. Assemble a multiblock batch proof over Block 1 + Block 2.
5. In post_op for Block 2, apply_to_array_vec attempts to push the 16,385th entry
   into ArrayVec<Bytes32, 16384> → panic → prover aborts → batch unprovable.
```

### Citations

**File:** zk_ee/src/common_structs/logs_storage.rs (L25-25)
```rust
pub const MAX_NUMBER_OF_LOGS: u64 = 16_384;
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L311-316)
```rust
    pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
        self.list.iter().for_each(|el| {
            let log: L2ToL1Log = el.into();
            array_vec.push(log.hash())
        });
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L77-83)
```rust
    } else if !cfg!(feature = "resources_for_tester") && pubdata_used > system.get_pubdata_limit() {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block pubdata limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockPubdataLimitReached)
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L27-27)
```rust
    pub logs_storage: ArrayVec<Bytes32, 16384>,
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L109-110)
```rust
        io.logs_storage
            .apply_to_array_vec(&mut batch_data.logs_storage);
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L200-215)
```rust
    fn get_pubdata_limit(&self) -> u64 {
        self.pubdata_limit
    }
}

impl BlockMetadataFromOracle {
    pub fn new_for_test() -> Self {
        BlockMetadataFromOracle {
            eip1559_basefee: U256::from(1000u64),
            pubdata_price: U256::from(0u64),
            native_price: U256::from(10),
            block_number: 1,
            timestamp: 42,
            chain_id: 37,
            gas_limit: u64::MAX / 256,
            pubdata_limit: u64::MAX,
```
