### Title
Missing Intra-Batch Timestamp Monotonicity Check Allows Non-Decreasing Violation in Multi-Block Batch Public Input - (File: `basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

`ZKBatchDataKeeper::apply_block` accumulates per-block data into a multi-block batch but never asserts that each successive block's timestamp is ≥ the previous block's timestamp within the batch. The per-block proving check only compares the current block's timestamp against the oracle-supplied `ProofData.last_block_timestamp`, which is the pre-batch state value — not the previous block's timestamp. A prover who supplies the same pre-batch `last_block_timestamp` for every block in the batch can produce a cryptographically valid proof where `first_block_timestamp > last_block_timestamp` in the committed `BatchOutput`.

---

### Finding Description

The `ChainStateCommitment` struct's own documentation states its `last_block_timestamp` field exists "to ensure that block timestamps are not decreasing." [1](#0-0) 

The per-block proving path enforces this with:

```rust
// validate that timestamp didn't decrease
assert!(metadata.block_timestamp() >= last_block_timestamp);
``` [2](#0-1) [3](#0-2) 

Here `last_block_timestamp` comes from `ProofData` queried via `ZKProofDataQuery::get` — the oracle-provided pre-batch state: [4](#0-3) 

In a multi-block batch, the proving loop runs `ProvingBootloader::run_prepared` once per block, each time consuming the next oracle item: [5](#0-4) 

The prover controls the oracle input stream. Nothing in the proving code validates that `ProofData.last_block_timestamp` for block N equals the timestamp of block N-1. A prover can supply the same pre-batch `last_block_timestamp` (e.g., `50`) for every block's `ProofData` query.

When `apply_block` is called for the second and subsequent blocks, it simply overwrites `current_block_timestamp` with no ordering assertion:

```rust
} else {
    assert_eq!(self.current_state_commitment.unwrap(), state_commitment_before);
    self.current_state_commitment = Some(state_commitment_after);
    self.current_block_timestamp = Some(block_timestamp);  // ← no ordering check
    assert_eq!(self.chain_id.unwrap(), chain_id);
    ...
}
``` [6](#0-5) 

The missing check is `assert!(block_timestamp >= self.current_block_timestamp.unwrap())`.

The resulting `BatchOutput` is constructed with: [7](#0-6) 

If block timestamps within the batch are, e.g., `[100, 80, 60]`, the `BatchOutput` will contain `first_block_timestamp = 100` and `last_block_timestamp = 60`, which is committed to the settlement layer as a valid proof output.

---

### Impact Explanation

**State-transition bug / valid-execution unprovability divergence.** A malicious prover can produce a cryptographically valid ZK proof for a batch where `first_block_timestamp > last_block_timestamp`. This batch public input is committed on the settlement layer. Downstream effects include:

1. **L2 smart contracts relying on `block.timestamp`** (time-locks, auctions, vesting schedules, lockup periods) observe non-monotonic timestamps across blocks within the batch, enabling bypass of time-based guards.
2. **The `ChainStateCommitment.last_block_timestamp`** committed after the batch is the timestamp of the last (lowest) block, corrupting the baseline for the next batch's monotonicity check.
3. **Settlement layer contracts** that validate `first_block_timestamp ≤ last_block_timestamp` will reject the batch, causing a liveness failure.

---

### Likelihood Explanation

The prover/forward execution input is an explicitly listed attacker entry point in the scope. The oracle input stream is entirely prover-controlled in the RISC-V proving context. No privileged key or governance action is required — only the ability to craft oracle responses, which is the prover's normal role. The missing assertion is a single line; the path to exploitation is direct.

---

### Recommendation

Add a timestamp ordering assertion in `ZKBatchDataKeeper::apply_block` for non-first blocks:

```rust
} else {
    assert_eq!(self.current_state_commitment.unwrap(), state_commitment_before);
    // Enforce monotonic timestamp ordering within the batch
    assert!(block_timestamp >= self.current_block_timestamp.unwrap(),
        "block timestamp must not decrease within a batch");
    self.current_state_commitment = Some(state_commitment_after);
    self.current_block_timestamp = Some(block_timestamp);
    ...
}
``` [6](#0-5) 

Additionally, the per-block proving check should use `>` (strict) rather than `>=` if equal timestamps within a batch are not intended, to match the `ChainStateCommitment` design intent.

---

### Proof of Concept

1. Prover constructs a multi-block batch with three blocks: timestamps `[100, 80, 60]`.
2. For each block's `ZKProofDataQuery` response, the prover supplies `ProofData { last_block_timestamp: 50, ... }` (the pre-batch value).
3. Per-block checks: `100 >= 50` ✓, `80 >= 50` ✓, `60 >= 50` ✓ — all pass.
4. `ZKBatchDataKeeper::apply_block` is called three times; `current_block_timestamp` is set to `100`, then `80`, then `60` with no assertion failure.
5. `into_public_input` produces `BatchOutput { first_block_timestamp: 100, last_block_timestamp: 60 }`. [7](#0-6) 

6. This is hashed and committed as the batch public input on the settlement layer, with `first_block_timestamp > last_block_timestamp` — a provably invalid ordering that the system's own design documentation states must not occur. [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L9-13)
```rust
/// - state commitment(`state_root` and `next_free_slot`)
/// - block number
/// - last 256 block hashes, previous can be "unrolled" from the last, but we commit to 256 for optimization.
/// - last block timestamp, to ensure that block timestamps are not decreasing.
///
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L52-58)
```rust
pub struct BatchOutput {
    /// Chain id used during execution of the blocks.
    pub chain_id: U256,
    /// First block timestamp.
    pub first_block_timestamp: u64,
    /// Last block timestamp.
    pub last_block_timestamp: u64,
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L115-120)
```rust
        let (mut state_commitment, last_block_timestamp) = {
            let proof_data: ProofData<FlatStorageCommitment<TREE_HEIGHT>> =
                ZKProofDataQuery::get(&mut io.oracle, &())
                    .expect("must get proof data from oracle");
            (proof_data.state_root_view, proof_data.last_block_timestamp)
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L127-128)
```rust
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L132-133)
```rust
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);
```

**File:** proof_running_system/src/system/bootloader.rs (L218-234)
```rust
    let mut batch_data = basic_bootloader::bootloader::block_flow::ZKBatchDataKeeper::new();
    for _ in 0..count {
        oracle = ProvingBootloader::<O, L>::run_prepared::<BasicBootloaderProvingExecutionConfig>(
            oracle,
            &mut batch_data,
            &mut NopResultKeeper::default(),
            &mut NopTracer::default(),
            &mut NopTxValidator,
        )
        .expect("Tried to prove a failing batch");
        // we do this query for consistency with block based input generation(there is empty iterator as response to this query)
        // but during proving this request shouldn't have the effect with "u32 array based" oracle
        #[allow(unused_must_use)]
        oracle
            .raw_query_with_empty_input(DISCONNECT_ORACLE_QUERY_ID)
            .expect("must disconnect an oracle before performing arbitrary CSR access");
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L84-97)
```rust
        } else {
            assert_eq!(
                self.current_state_commitment.unwrap(),
                state_commitment_before
            );
            self.current_state_commitment = Some(state_commitment_after);
            self.current_block_timestamp = Some(block_timestamp);
            assert_eq!(self.chain_id.unwrap(), chain_id);
            assert!(upgrade_tx_hash.is_zero());
            assert_eq!(
                self.settlement_layer_chain_id,
                Some(settlement_layer_chain_id)
            );
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L139-152)
```rust
        let batch_output = BatchOutput {
            chain_id: self.chain_id.unwrap(),
            first_block_timestamp: self.first_block_timestamp.unwrap(),
            last_block_timestamp: self.current_block_timestamp.unwrap(),
            da_commitment_scheme: self.da_commitment_scheme.unwrap(),
            pubdata_commitment: self.da_commitment_generator.unwrap().finalize(oracle),
            number_of_layer_1_txs,
            number_of_layer_2_txs,
            priority_operations_hash,
            l2_logs_tree_root: chain_batch_root.into(),
            upgrade_tx_hash: self.upgrade_tx_hash.unwrap(),
            interop_roots_rolling_hash: self.interop_roots_rolling_hash,
            settlement_layer_chain_id: self.settlement_layer_chain_id.unwrap(),
        };
```
