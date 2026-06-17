### Title
Missing Intra-Batch Block Timestamp Monotonicity Enforcement Allows Decreasing Timestamps Within a Multiblock Batch - (File: `basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs`)

---

### Summary

Within a multiblock batch, `ZKBatchDataKeeper::apply_block()` updates `current_block_timestamp` for each successive block but never asserts that the new block's timestamp is greater than or equal to the previous block's timestamp within the same batch. The only timestamp monotonicity check that exists compares each block's timestamp against the oracle-provided `ProofData.last_block_timestamp`, which represents the last timestamp of the **previous batch** — not the previous block within the current batch. A malicious prover can supply oracle data with decreasing timestamps for consecutive blocks in a multiblock batch, producing a provably valid state transition that violates the EVM invariant that `block.timestamp` is non-decreasing.

---

### Finding Description

In `post_tx_op_proving_multiblock_batch.rs`, for every block processed in a multiblock batch, the following check is performed:

```rust
// validate that timestamp didn't decrease
assert!(metadata.block_timestamp() >= last_block_timestamp);
``` [1](#0-0) 

Here, `last_block_timestamp` is read from the oracle's `ProofData`:

```rust
let (mut state_commitment, last_block_timestamp) = {
    let proof_data: ProofData<FlatStorageCommitment<TREE_HEIGHT>> =
        ZKProofDataQuery::get(&mut io.oracle, &())
            .expect("must get proof data from oracle");
    (proof_data.state_root_view, proof_data.last_block_timestamp)
};
``` [2](#0-1) 

This `last_block_timestamp` is the last timestamp of the **previous batch** (from the on-chain `ChainStateCommitment`), not the timestamp of the previous block within the current batch. The oracle provides this value externally and it is not cross-validated against the batch accumulator's internal state.

When `apply_block()` is called for subsequent blocks in the batch, it unconditionally overwrites `current_block_timestamp` with no monotonicity assertion:

```rust
} else {
    // ...
    self.current_block_timestamp = Some(block_timestamp);  // no >= check
    // ...
}
``` [3](#0-2) 

The `current_block_timestamp` field exists in `ZKBatchDataKeeper` and is used as `last_block_timestamp` in the final `BatchOutput`, but it is never used to enforce monotonicity against incoming blocks: [4](#0-3) 

The block metadata (including `timestamp`) is sourced from the oracle via `BLOCK_METADATA_QUERY_ID`: [5](#0-4) 

In the proving path, oracle data is provided externally as part of the proof input and is treated as untrusted input per the system's own documentation: [6](#0-5) 

---

### Impact Explanation

A malicious prover can craft a multiblock batch where:
- Block N has timestamp `T + 100`
- Block N+1 has timestamp `T + 1` (less than Block N)

Both blocks pass the check `metadata.block_timestamp() >= last_block_timestamp` because `last_block_timestamp` is the previous batch's last timestamp `T`, not Block N's timestamp. The batch accumulator accepts both without complaint.

The resulting `ChainStateCommitment` after the batch records `last_block_timestamp = T + 1` (the last block's timestamp), which is less than an intermediate block's timestamp. This violates the EVM invariant that `block.timestamp` is non-decreasing.

Smart contracts relying on `block.timestamp` for time-based logic — such as time locks, expiry checks, or auction deadlines — can be exploited. For example, a contract with `require(block.timestamp >= deadline)` that succeeds in Block N (timestamp `T+100`) could be re-entered or replayed in Block N+1 (timestamp `T+1`) in a context where the earlier timestamp causes the check to fail or behave unexpectedly, or vice versa.

The `BatchOutput.last_block_timestamp` committed to the settlement layer will also be incorrect, corrupting the `ChainStateCommitment` used for subsequent batch validation: [7](#0-6) 

---

### Likelihood Explanation

The attacker-controlled entry path is the **prover/forward execution input**: the oracle data (block metadata and `ProofData`) is provided externally to the RISC-V proving environment. A malicious or compromised sequencer/prover who constructs the multiblock batch proof input can supply decreasing timestamps for consecutive blocks. No privileged key or governance majority is required beyond the ability to submit a batch proof — which is the normal operational role of the prover in a ZK rollup. The missing check is a single missing assertion in `apply_block()`, making exploitation straightforward once the attacker controls the oracle input.

---

### Recommendation

In `ZKBatchDataKeeper::apply_block()`, add a monotonicity assertion for subsequent blocks:

```rust
} else {
    assert_eq!(
        self.current_state_commitment.unwrap(),
        state_commitment_before
    );
    // Enforce non-decreasing timestamps within the batch
    assert!(
        block_timestamp >= self.current_block_timestamp.unwrap(),
        "block timestamp must not decrease within a batch"
    );
    self.current_block_timestamp = Some(block_timestamp);
    // ...
}
``` [3](#0-2) 

Additionally, the oracle-provided `ProofData.last_block_timestamp` for each block beyond the first in a multiblock batch should be cross-validated against `self.current_block_timestamp` in the batch accumulator, rather than relying solely on the oracle-supplied value.

---

### Proof of Concept

1. Construct a multiblock batch with two blocks:
   - Block 1: oracle provides `BlockMetadataFromOracle { timestamp: 1000, ... }` and `ProofData { last_block_timestamp: 500 }` (previous batch's last timestamp)
   - Block 2: oracle provides `BlockMetadataFromOracle { timestamp: 600, ... }` and `ProofData { last_block_timestamp: 500 }` (same previous batch value, not Block 1's 1000)

2. Block 1 passes: `1000 >= 500` ✓. `apply_block` sets `current_block_timestamp = 1000`.

3. Block 2 passes: `600 >= 500` ✓. `apply_block` sets `current_block_timestamp = 600` with no check against `1000`.

4. The batch finalizes with `first_block_timestamp = 1000`, `last_block_timestamp = 600` — a decreasing sequence — committed to the settlement layer. [1](#0-0) [3](#0-2) [7](#0-6)

### Citations

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

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L22-24)
```rust
    first_block_timestamp: Option<u64>,
    current_block_timestamp: Option<u64>,
    chain_id: Option<U256>,
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L139-142)
```rust
        let batch_output = BatchOutput {
            chain_id: self.chain_id.unwrap(),
            first_block_timestamp: self.first_block_timestamp.unwrap(),
            last_block_timestamp: self.current_block_timestamp.unwrap(),
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs (L18-19)
```rust
        let block_level_metadata: BlockMetadataFromOracle =
            oracle.query_with_empty_input(BLOCK_METADATA_QUERY_ID)?;
```

**File:** docs/system/io/oracles.md (L82-86)
```markdown
**Important**: Oracle responses are non-deterministic and MUST be treated as untrusted input. All responses should be:

- Treated as opaque byte arrays, or
- Validated against additional constraints during deserialization or usage

```
