### Title
Unbounded L2-to-L1 Log Accumulation Panics Fixed-Capacity `ArrayVec` During Batch Finalization — (`basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

`ZKBatchDataKeeper` accumulates L2-to-L1 log hashes into a fixed-capacity `ArrayVec<Bytes32, 16384>`. The function `LogsStorage::apply_to_array_vec` pushes every log hash into this buffer without any capacity guard. `ArrayVec::push` panics on overflow. If the total number of L2-to-L1 logs committed across all blocks in a batch exceeds 16 384, the batch-finalization step panics in both the forward (sequencer) and proving (RISC-V) paths, making the batch permanently unprovable and halting the chain.

---

### Finding Description

`ZKBatchDataKeeper` holds a batch-level log accumulator:

```rust
pub logs_storage: ArrayVec<Bytes32, 16384>,
``` [1](#0-0) 

After each block is processed, the block's `LogsStorage` is drained into this accumulator via:

```rust
pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
    self.list.iter().for_each(|el| {
        let log: L2ToL1Log = el.into();
        array_vec.push(log.hash())   // panics when len == 16384
    });
}
``` [2](#0-1) 

`arrayvec::ArrayVec::push` panics unconditionally when the vector is full; there is no `try_push` or capacity check here.

At batch finalization, `into_public_input` consumes `self.logs_storage` to compute the Merkle root that becomes part of the on-chain public input:

```rust
chain_batch_root_hasher.update(Self::l2_logs_root(self.logs_storage).as_u8_ref());
``` [3](#0-2) 

The tree-height constant is 14, matching exactly 2^14 = 16 384 leaves — the capacity of the `ArrayVec`. The documentation confirms this is a hard design limit:

> "This is going to be a fixed-size (16384) Merkle tree." [4](#0-3) 

There is no enforcement anywhere in the transaction-processing or block-sealing code that caps the *cumulative* log count across a multi-block batch at 16 383. Per-transaction pubdata limits are enforced per block, but a batch can span many blocks. Two blocks each contributing 9 000 logs (well within a single-block pubdata budget) would push the batch total to 18 000, overflowing the accumulator.

---

### Impact Explanation

When the 16 385th log hash is pushed, `ArrayVec::push` panics. In the proving path (RISC-V binary), a panic aborts proof generation; the batch can never be proven and the rollup halts. In the forward path (sequencer), the same panic crashes block finalization, preventing the sequencer from sealing the batch. The state is permanently stuck: the batch cannot be finalized, proven, or submitted to L1.

This is a **valid-execution unprovability** / **state-transition DoS** bug: the execution is valid per EVM rules, but the ZKsync OS infrastructure cannot finalize it.

---

### Likelihood Explanation

L2-to-L1 logs are emitted by:
1. Every L1→L2 (priority) transaction result — one log per L1 tx.
2. User messages sent via the L1 Messenger system hook — one log per `sendToL1` call.

An attacker deploys a contract that calls the L1 Messenger in a loop. Each iteration costs gas but produces one log. With a block gas limit of, say, 30 M gas and ~5 000 gas per L1 Messenger call, a single transaction can emit ~6 000 logs. Three such transactions across two blocks in one batch exceed 16 384. The operator's per-block `pubdata_limit` (88 bytes × 16 384 = ~1.44 MB) is the only guard, but:

- The default test value is `pubdata_limit: u64::MAX`.
- No code enforces a *batch-level* log count ceiling.
- The `pubdata_limit` field is oracle-supplied and not cryptographically constrained in the proving path. [5](#0-4) 

---

### Recommendation

1. **Add a capacity check in `apply_to_array_vec`**: replace `array_vec.push(log.hash())` with `array_vec.try_push(log.hash()).expect("L2-to-L1 log limit exceeded")` and propagate the error gracefully, or enforce the limit earlier.

2. **Enforce a batch-level log count ceiling** in the block-sealing path: before committing a block's logs to the batch accumulator, verify that `batch_data.logs_storage.len() + block_logs.len() <= 16384` and reject/truncate the block if the limit would be exceeded.

3. **Align the per-block pubdata limit with the batch log capacity**: ensure the operator-supplied `pubdata_limit` is set such that no single block can contribute enough logs to overflow the batch accumulator when combined with logs from other blocks in the same batch.

---

### Proof of Concept

```
1. Attacker deploys contract C:
     loop 6000 times:
       call L1Messenger.sendToL1(bytes("x"))   // emits 1 L2-to-L1 log each

2. Attacker submits 3 transactions calling C, spread across 2 blocks in one batch.
   Total logs: 3 × 6000 = 18 000 > 16 384.

3. When the sequencer calls apply_to_array_vec for the second block's logs,
   the 16 385th push panics:
     thread 'main' panicked at 'index out of bounds' (ArrayVec capacity exceeded)

4. Batch finalization aborts. The proving binary also panics on the same path.
   The batch is permanently unprovable; the rollup halts.
```

The root cause is in `zk_ee/src/common_structs/logs_storage.rs` line 314 (`array_vec.push`) and the fixed capacity declaration in `basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs` line 27, with no intervening guard anywhere in the call chain. [6](#0-5) [1](#0-0)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L27-27)
```rust
    pub logs_storage: ArrayVec<Bytes32, 16384>,
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L126-126)
```rust
        chain_batch_root_hasher.update(Self::l2_logs_root(self.logs_storage).as_u8_ref());
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

**File:** docs/l1_integration.md (L120-120)
```markdown
This is going to be a fixed-size (16384) Merkle tree.
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L200-202)
```rust
    fn get_pubdata_limit(&self) -> u64 {
        self.pubdata_limit
    }
```
