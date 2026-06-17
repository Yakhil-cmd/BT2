### Title
Multiblock Batch Prover Panic via `ArrayVec` Overflow in `ZKBatchDataKeeper.logs_storage` - (`basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

In ZKsync OS's multiblock batch proving path, the `ZKBatchDataKeeper` accumulates L2→L1 log hashes from every block in a batch into a fixed-capacity `ArrayVec<Bytes32, 16384>`. Because the per-block log limit is also 16,384, a batch containing two or more blocks that each reach the per-block log limit will cause `ArrayVec::push` to panic when the second block's logs are appended. An unprivileged attacker can deliberately fill the per-block log quota across consecutive blocks, forcing the prover to crash on any multiblock batch that includes those blocks.

---

### Finding Description

**Bounded accumulator with insufficient capacity for multiblock batches**

`ZKBatchDataKeeper` holds a batch-level log accumulator:

```rust
pub logs_storage: ArrayVec<Bytes32, 16384>,
``` [1](#0-0) 

At the end of each block's proving step (`ZKHeaderStructurePostTxOpProvingMultiblockBatch::post_op`), the block's logs are appended to this accumulator:

```rust
io.logs_storage
    .apply_to_array_vec(&mut batch_data.logs_storage);
``` [2](#0-1) 

`apply_to_array_vec` uses `ArrayVec::push` (not `try_push`) for every log:

```rust
pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
    self.list.iter().for_each(|el| {
        let log: L2ToL1Log = el.into();
        array_vec.push(log.hash())   // panics if full
    });
}
``` [3](#0-2) 

The per-block log limit is enforced in `check_for_block_limits`:

```rust
} else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
    Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
``` [4](#0-3) 

where `MAX_NUMBER_OF_LOGS = 16_384`: [5](#0-4) 

The per-block limit and the batch accumulator capacity are **identical** (16,384). A batch containing two blocks each with 16,384 logs would require the accumulator to hold 32,768 entries — double its capacity. The `ArrayVec::push` call for the second block's first log panics unconditionally.

The attacker entry point is the L1 Messenger system hook at address `0x7001`, callable by any user via the L1 Messenger system contract at `0x8008` using `sendToL1(bytes)`: [6](#0-5) 

Each `sendToL1` call produces one L2→L1 log entry via `emit_l1_message` → `logs_storage.push_message`: [7](#0-6) 

---

### Impact Explanation

When the prover executes `apply_to_array_vec` for the second (or later) block in a multiblock batch and the accumulator is already at capacity, the Rust `ArrayVec::push` panics. In the RISC-V proving environment this is a fatal, unrecoverable abort of the proving run. The batch cannot be finalized on L1 until the operator restructures the batch to contain only one block — but if the attacker continuously fills every block's log quota, every multiblock batch attempt will fail. This constitutes a sustained DoS on L1 finalization for multiblock batches, delaying or blocking settlement-layer state updates and user withdrawals.

---

### Likelihood Explanation

The L1 Messenger is permissionlessly callable by any EOA or contract. Filling 16,384 log slots per block requires sending 16,384 `sendToL1` calls; at L2 gas prices this is cheap. The attacker only needs to saturate one block and have any log in the next block of the same batch. Because the operator has no on-chain mechanism to prevent two log-heavy blocks from being batched together, the attacker can reliably trigger the panic on every multiblock proving attempt.

---

### Recommendation

Replace the fixed-capacity `ArrayVec<Bytes32, 16384>` in `ZKBatchDataKeeper` with a dynamically-sized container (e.g., `Vec<Bytes32, A>`) whose capacity grows with the number of blocks in the batch. Alternatively, replace `apply_to_array_vec`'s use of `ArrayVec::push` with `try_push` and propagate the error gracefully rather than panicking. The batch accumulator capacity must be at least `MAX_NUMBER_OF_LOGS × (maximum blocks per batch)`.

---

### Proof of Concept

1. Attacker deploys a contract that calls `L1Messenger.sendToL1(bytes)` in a loop.
2. In block N, the attacker submits enough transactions to emit exactly 16,384 L2→L1 logs, reaching `MAX_NUMBER_OF_LOGS`. The block is accepted.
3. In block N+1, the attacker submits one more transaction that emits at least 1 L2→L1 log.
4. The operator seals both blocks and initiates a multiblock batch proof.
5. During proving, `post_op` for block N fills `batch_data.logs_storage` to capacity (16,384 entries).
6. `post_op` for block N+1 calls `io.logs_storage.apply_to_array_vec(&mut batch_data.logs_storage)`, which calls `ArrayVec::push` on a full array — **panic**.
7. The prover process aborts; the batch cannot be submitted to L1. [1](#0-0) [8](#0-7) [2](#0-1)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L27-27)
```rust
    pub logs_storage: ArrayVec<Bytes32, 16384>,
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L109-110)
```rust
        io.logs_storage
            .apply_to_array_vec(&mut batch_data.logs_storage);
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L24-25)
```rust
// Taken from the size of the Merkle tree.
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

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L136-163)
```rust
pub(crate) fn send_to_l1_inner<S: EthereumLikeTypes>(
    calldata: &[u8],
    resources: &mut S::Resources,
    system: &mut System<S>,
) -> Result<Result<(), &'static str>, SystemError> {
    if calldata.len() < 20 {
        return Ok(Err(
            "L1 messenger failure: sendToL1 called with invalid calldata",
        ));
    }

    let address_sender = B160::try_from_be_slice(&calldata[0..20]).ok_or(
        SystemError::LeafDefect(internal_error!("Failed to create B160 from 20 byte array")),
    )?;

    let message = &calldata[20..];

    // emit L1 message (ignore returned hash)
    // TODO(EVM-1190): hash calculation is suboptimal, to be refactored in future
    system.io.emit_l1_message(
        // Gas should be charged by the L1Messenger system contract
        ExecutionEnvironmentType::NoEE,
        resources,
        &address_sender,
        message,
    )?;

    Ok(Ok(()))
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L185-227)
```rust
    fn emit_l1_message(
        &mut self,
        _ee_type: ExecutionEnvironmentType,
        resources: &mut Self::Resources,
        address: &<Self::IOTypes as SystemIOTypesConfig>::Address,
        data: &[u8],
    ) -> Result<Bytes32, SystemError> {
        // TODO(EVM-1077): consider adding COMPUTATIONAL_PRICE_FOR_PUBDATA as in Era

        // We need to charge cost of hashing:
        // - keccak256_native_cost(L2_TO_L1_LOG_SERIALIZE_SIZE) and
        //   keccak256_native_cost(64) when reconstructing L2ToL1Log
        // - keccak256_native_cost(64) + keccak256_native_cost(data.len())
        //   when reconstructing Messages
        // - at most 1 time keccak256_native_cost(64) when building the
        //   Merkle tree (as merkle tree can contain ~2*N nodes, where the
        //   first N nodes are leaves the hash of which is calculated on the
        //   previous step).

        let hashing_native_cost =
            keccak256_native_cost::<Self::Resources>(L2_TO_L1_LOG_SERIALIZE_SIZE).as_u64()
                + 3 * keccak256_native_cost::<Self::Resources>(64).as_u64()
                + keccak256_native_cost::<Self::Resources>(data.len()).as_u64();

        // We also charge some native resource for storing the log
        let native = hashing_native_cost
            + EVENT_STORAGE_BASE_NATIVE_COST
            + EVENT_DATA_PER_BYTE_COST * (data.len() as u64);

        resources.charge(&R::from_native(R::Native::from_computational(native)))?;

        // TODO(EVM-1078): for Era backward compatibility we may need to add events for l2 to l1 log and l1 message

        // Compute data hash directly: the native cost for this keccak is already
        // pre-charged above (included in `hashing_native_cost`), and this function
        // must not charge ergs — EVM gas accounting is the caller's responsibility
        // (the L1Messenger system contract charges it before invoking the hook).
        use crypto::MiniDigest;
        let data_hash = Bytes32::from_array(crypto::sha3::Keccak256::digest(data));
        let data = UsizeAlignedByteBox::from_slice_in(data, self.allocator.clone());
        self.logs_storage
            .push_message(self.tx_number, address, data, data_hash)?;
        Ok(data_hash)
```
