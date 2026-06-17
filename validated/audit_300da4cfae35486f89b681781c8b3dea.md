### Title
Non-Strict Block Timestamp Monotonicity Check Allows Equal Consecutive Timestamps — (`File: basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs` and `post_tx_op_proving_multiblock_batch.rs`)

---

### Summary

Both the single-block and multi-block batch proving paths enforce timestamp monotonicity using a non-strict `>=` comparison instead of the strict `>` required by the Ethereum specification. This allows a sequencer to produce consecutive L2 blocks with identical timestamps, which the ZK proof system will accept and finalize. Smart contracts relying on strictly increasing `block.timestamp` values are exposed to semantic breakage.

---

### Finding Description

In both proving-mode post-transaction operations, the only timestamp validation is:

```rust
// validate that timestamp didn't decrease
assert!(metadata.block_timestamp() >= last_block_timestamp);
```

This appears in:
- `post_tx_op_proving_singleblock_batch.rs` line 133
- `post_tx_op_proving_multiblock_batch.rs` line 128

The `last_block_timestamp` is sourced from `ProofData` queried from the oracle, which carries the previous block's timestamp as committed in `ChainStateCommitment`. The commitment chain in `apply_block` (via `assert_eq!` on state commitment hashes) cryptographically binds each block's `last_block_timestamp` to the actual previous block's timestamp, so the oracle cannot lie about it. The `>=` check is therefore the sole and authoritative enforcement gate.

The Ethereum Yellow Paper (and EIP-1559 / post-merge spec) requires:

> "The scalar value equal to the reasonable output of Unix's time() at this block's inception; **must be greater than the parent block's timestamp**."

`>=` permits equality, meaning two consecutive blocks may carry the same `block.timestamp`. The `ChainStateCommitment` struct itself documents the intent as "to ensure that block timestamps are **not decreasing**" — confirming the design only targets non-decrease, not strict increase.

In `apply_block` (the multi-block accumulator), there is also no inter-block timestamp monotonicity check:

```rust
} else {
    // ...
    self.current_block_timestamp = Some(block_timestamp); // no assert vs previous
    // ...
}
```

While the commitment chain prevents oracle manipulation of `last_block_timestamp`, the `>=` gate itself is the protocol rule, and it is weaker than the Ethereum spec.

---

### Impact Explanation

**Vulnerability class:** EVM semantic mismatch / state-transition bug.

- The `TIMESTAMP` opcode (`0x42`) returns `block.timestamp`. If two consecutive blocks share the same timestamp, any contract logic of the form `require(block.timestamp > lastSeen)` will revert on the second block even for legitimate callers.
- Time-locked contracts (vesting, escrow release, governance timelocks), auction end-time checks, rate limiters, and TWAP oracles that assume strictly increasing timestamps can be broken or manipulated.
- A sequencer can deliberately set `block N+1.timestamp == block N.timestamp`. The proof verifies correctly (the `>=` check passes), the settlement layer accepts the batch, and the equal-timestamp state is finalized on-chain. There is no recovery path for affected contracts.
- The `BatchOutput` committed to the settlement layer includes `first_block_timestamp` and `last_block_timestamp`; equal values across a batch are accepted without rejection.

---

### Likelihood Explanation

The sequencer controls `BlockMetadataFromOracle.timestamp` (set via `BlockContext` in the forward path, then replayed in the proving path). No external attacker input is required beyond the sequencer choosing to set equal timestamps — either accidentally (clock resolution, rapid block production) or deliberately. The proof system provides no backstop. The `>=` check is the only enforcement, and it explicitly permits equality.

---

### Recommendation

Replace the non-strict check with a strict inequality in both proving paths:

```rust
// Enforce strictly increasing timestamps per Ethereum spec
assert!(metadata.block_timestamp() > last_block_timestamp);
```

Apply this change to:
- `post_tx_op_proving_singleblock_batch.rs` line 133
- `post_tx_op_proving_multiblock_batch.rs` line 128

Additionally, add a corresponding inter-block check inside `apply_block` in `batch_data.rs` for defense-in-depth:

```rust
} else {
    // ...
    assert!(block_timestamp > self.current_block_timestamp.unwrap(),
        "block timestamps must be strictly increasing");
    self.current_block_timestamp = Some(block_timestamp);
    // ...
}
```

---

### Proof of Concept

1. Sequencer produces Block N with `timestamp = T`.
2. Sequencer produces Block N+1 with `timestamp = T` (same value).
3. In the proving path for Block N+1, `ProofData.last_block_timestamp = T` (committed via `ChainStateCommitment` of Block N).
4. The check `assert!(T >= T)` passes.
5. `apply_block` records `current_block_timestamp = T` without complaint.
6. `BatchOutput.first_block_timestamp = T`, `last_block_timestamp = T` — accepted.
7. The ZK proof is generated and verified on the settlement layer.
8. Any contract on Block N+1 calling `require(block.timestamp > lastActionTimestamp)` where `lastActionTimestamp` was set in Block N will revert, even though real time has advanced.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L11-12)
```rust
/// - last 256 block hashes, previous can be "unrolled" from the last, but we commit to 256 for optimization.
/// - last block timestamp, to ensure that block timestamps are not decreasing.
```

**File:** zk_ee/src/common_structs/proof_data.rs (L11-18)
```rust
/// We'll validate reads/apply writes against `state_root_view` and validate that block timestamp is greater than `last_block_timestamp`.
/// At the end we'll calculate chain state commitment before using this fields and other metadata values(block number, hashes) used during execution.
///
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofData<SR: StateRootView<EthereumIOTypesConfig>> {
    pub state_root_view: SR,
    pub last_block_timestamp: u64,
```
