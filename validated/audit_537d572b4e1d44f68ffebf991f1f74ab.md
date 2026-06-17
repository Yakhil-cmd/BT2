### Title
Non-Strict Block Timestamp Monotonicity Check Allows Equal-Timestamp Blocks to Be Proven — (`basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs`)

---

### Summary

The ZK proving path enforces timestamp monotonicity with a non-strict `>=` comparison, while the authoritative documentation for `ProofData` explicitly states the invariant must be **strictly greater than**. This discrepancy allows a prover to submit a block whose timestamp equals the previous block's timestamp, causing the `TIMESTAMP` opcode to return a stale value and breaking time-period enforcement in any smart contract deployed on ZKsync OS that relies on `block.timestamp` advancing between blocks.

---

### Finding Description

In both the single-block and multi-block batch proving post-operations, the timestamp check reads:

```rust
// validate that timestamp didn't decrease
assert!(metadata.block_timestamp() >= last_block_timestamp);
``` [1](#0-0) [2](#0-1) 

The `>=` operator permits `metadata.block_timestamp() == last_block_timestamp`.

The canonical specification for `ProofData` states the opposite:

> "We'll validate reads/apply writes against `state_root_view` and validate that block timestamp is **greater than** `last_block_timestamp`." [3](#0-2) 

`last_block_timestamp` is read from the oracle-supplied `ProofData` and is committed into `ChainStateCommitment` as the authoritative previous-block timestamp: [4](#0-3) 

The `ChainStateCommitment` struct itself documents `last_block_timestamp` as existing "to ensure that block timestamps are not decreasing": [5](#0-4) 

The `TIMESTAMP` opcode is served directly from `system.get_timestamp()` → `metadata.block_timestamp()`: [6](#0-5) [7](#0-6) 

Because the ZK constraint only enforces `>=`, a valid proof can be generated for a block whose `TIMESTAMP` is identical to the previous block's `TIMESTAMP`. Any EVM contract that uses `block.timestamp` to enforce a time-period boundary (e.g., `require(block.timestamp > periodEnd)`) will observe no time progression between those two blocks, making the period-end check bypassable.

---

### Impact Explanation

The vulnerability class is **temporal access control bug / missing strict time-bound enforcement** — a direct analog to the reference report.

- The `TIMESTAMP` opcode returns the same value for two consecutive proven blocks.
- Smart contracts that gate actions on `block.timestamp > deadline` or `block.timestamp > lastActionTime` can be re-entered within the same timestamp window, defeating the intended time-period boundary.
- The `ChainStateCommitment` written to the settlement layer will carry `last_block_timestamp == current_block_timestamp`, which is accepted by the `>=` check in the next block's proof, allowing the condition to persist across an arbitrary chain of blocks.
- This is a **state-transition / EVM semantic mismatch** bug: the EVM contract author's assumption that `block.timestamp` strictly increases between blocks is violated by the ZK proof system.

---

### Likelihood Explanation

The prover/forward execution input is an explicitly listed attacker entry point in the Immunefi scope. The prover supplies both the `BlockMetadataFromOracle` (which sets `metadata.block_timestamp()`) and the `ProofData` oracle response (which sets `last_block_timestamp`). Because the ZK constraint only checks `>=`, the prover can legally set `metadata.block_timestamp() == last_block_timestamp` and produce a valid proof. No privileged key or governance majority is required beyond the prover role itself. [8](#0-7) 

---

### Recommendation

Replace the non-strict comparison with a strict one in both proving post-operations, consistent with the documented invariant:

```rust
// validate that timestamp strictly increased
assert!(metadata.block_timestamp() > last_block_timestamp);
``` [1](#0-0) [2](#0-1) 

---

### Proof of Concept

1. Previous block N has `block_timestamp = T`; its `ChainStateCommitment` records `last_block_timestamp = T`.
2. Prover constructs block N+1 with `BlockMetadataFromOracle.timestamp = T` (same value).
3. Prover supplies `ProofData { last_block_timestamp: T, ... }` via the oracle.
4. The proving post-op evaluates `assert!(T >= T)` — this passes.
5. Block N+1 is proven and committed with `last_block_timestamp = T` in its `ChainStateCommitment`.
6. Any EVM contract executing in block N+1 that calls `TIMESTAMP` receives `T`, identical to block N.
7. A contract guarding an action with `require(block.timestamp > T)` (where `T` was set in block N) will revert, even though the intended period has "ended" from the user's perspective — or conversely, a contract using `require(block.timestamp <= T)` to restrict an action to a window will incorrectly allow it in block N+1.
8. The condition can be chained: block N+2 can also be proven with `timestamp = T` by the same logic, extending the stale-timestamp window indefinitely.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L120-125)
```rust
        let (mut state_commitment, last_block_timestamp) = {
            let proof_data: ProofData<FlatStorageCommitment<TREE_HEIGHT>> =
                ZKProofDataQuery::get(&mut io.oracle, &())
                    .expect("must get proof data from oracle");
            (proof_data.state_root_view, proof_data.last_block_timestamp)
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L132-133)
```rust
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L127-128)
```rust
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);
```

**File:** zk_ee/src/common_structs/proof_data.rs (L9-12)
```rust
/// During proof run we need extra data to validate provided inputs against chain state commitment before the block.
///
/// We'll validate reads/apply writes against `state_root_view` and validate that block timestamp is greater than `last_block_timestamp`.
/// At the end we'll calculate chain state commitment before using this fields and other metadata values(block number, hashes) used during execution.
```

**File:** zk_ee/src/common_structs/proof_data.rs (L16-19)
```rust
pub struct ProofData<SR: StateRootView<EthereumIOTypesConfig>> {
    pub state_root_view: SR,
    pub last_block_timestamp: u64,
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L8-24)
```rust
/// Commitment to state that we need to keep between blocks execution:
/// - state commitment(`state_root` and `next_free_slot`)
/// - block number
/// - last 256 block hashes, previous can be "unrolled" from the last, but we commit to 256 for optimization.
/// - last block timestamp, to ensure that block timestamps are not decreasing.
///
/// This commitment(hash of its fields) will be saved on the settlement layer.
/// With proofs, we'll ensure that the values used during block execution correspond to this commitment.
///
#[derive(Debug)]
pub struct ChainStateCommitment {
    pub state_root: Bytes32,
    pub next_free_slot: u64,
    pub block_number: u64,
    pub last_256_block_hashes_blake: Bytes32,
    pub last_block_timestamp: u64,
}
```

**File:** zk_ee/src/system/mod.rs (L172-174)
```rust
    pub fn get_timestamp(&self) -> u64 {
        self.metadata.block_timestamp()
    }
```

**File:** evm_interpreter/src/interpreter.rs (L279-279)
```rust
                    opcodes::TIMESTAMP => self.timestamp(system),
```
