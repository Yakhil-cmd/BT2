### Title
Unchecked `block_number - 1` Integer Underflow in ZK Proving Path Corrupts Genesis Block `ChainStateCommitment` — (`basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs` and `post_tx_op_proving_multiblock_batch.rs`)

---

### Summary

Both ZK proving post-transaction operations compute `metadata.block_number() - 1` unconditionally when constructing `chain_state_commitment_before`. For the genesis block (`block_number == 0`), this wraps to `u64::MAX` in Rust release mode (the RISC-V proving target), silently corrupting the `ChainStateCommitment` hash that feeds into `BatchPublicInput.state_before`. The forward execution path handles this case correctly (see `form_block_header`), but the proving path does not, creating a forward/proving divergence.

---

### Finding Description

In both `ZKHeaderStructurePostTxOpProvingSingleblockBatch::post_op` and `ZKHeaderStructurePostTxOpProvingMultiblockBatch::post_op`, the "before" chain state commitment is constructed as:

```rust
let chain_state_commitment_before = ChainStateCommitment {
    state_root: state_commitment.root,
    next_free_slot: state_commitment.next_free_slot,
    block_number: metadata.block_number() - 1,   // ← no zero-check
    last_256_block_hashes_blake: blocks_hasher.finalize().into(),
    last_block_timestamp,
};
``` [1](#0-0) [2](#0-1) 

When `block_number == 0` (genesis block), `0u64 - 1` wraps to `u64::MAX` in Rust release mode. This corrupts `chain_state_commitment_before.block_number`, which is then hashed into `BatchPublicInput.state_before`:

```rust
let public_input = BatchPublicInput {
    state_before: chain_state_commitment_before.hash().into(),  // wrong hash
    state_after:  chain_state_commitment_after.hash().into(),
    batch_output: batch_output.hash().into(),
};
``` [3](#0-2) 

By contrast, the forward-path helper `form_block_header` explicitly guards against this:

```rust
let previous_block_hash = if block_number == 0 {
    Bytes32::ZERO
} else {
    system.get_blockhash(block_number - 1)?
};
``` [4](#0-3) 

The developers are clearly aware that `block_number == 0` is a valid state (the genesis block test asserts `header.number == 0`), but the proving path lacks the same guard. [5](#0-4) 

---

### Impact Explanation

**Vulnerability class:** Forward/proving divergence + valid-execution unprovability.

The forward run succeeds for block 0. The proving run silently computes `block_number = u64::MAX` for `chain_state_commitment_before`, producing a wrong `state_before` hash in `BatchPublicInput`. The verifier will either:

1. **Reject the proof** — the genesis block is permanently unprovable, breaking chain bootstrapping.
2. **Accept the proof with wrong public inputs** — if the verifier is also misconfigured to expect `u64::MAX`, an attacker could anchor the chain to a fabricated initial state commitment.

Either outcome is a critical state-transition integrity failure.

---

### Likelihood Explanation

Block 0 is a valid, reachable block number in ZKsync OS (confirmed by the genesis block test). The proving path (`

### Title
Integer Underflow in Genesis Block Proof Public Input Calculation — (`basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs` and `post_tx_op_proving_multiblock_batch.rs`)

---

### Summary

Both ZK proving post-op implementations compute `metadata.block_number() - 1` without guarding against `block_number == 0`. When the genesis block (block number 0) is proven, this subtraction underflows. In Rust release mode — used for the RISC-V proving target — the result silently wraps to `u64::MAX`, embedding a corrupted `block_number` into `chain_state_commitment_before`, which is then hashed into the batch public input. The resulting proof commits to an incorrect "before" state, making the genesis block proof invalid or causing the verifier to accept a wrong state transition.

---

### Finding Description

In `post_tx_op_proving_singleblock_batch.rs` and `post_tx_op_proving_multiblock_batch.rs`, the `chain_state_commitment_before` struct is constructed as:

```rust
let chain_state_commitment_before = ChainStateCommitment {
    state_root: state_commitment.root,
    next_free_slot: state_commitment.next_free_slot,
    block_number: metadata.block_number() - 1,  // underflows when block_number == 0
    last_256_block_hashes_blake: blocks_hasher.finalize().into(),
    last_block_timestamp,
};
``` [1](#0-0) [2](#0-1) 

There is no guard for `block_number == 0`. The sibling function `form_block_header` in `mod.rs` correctly handles this case:

```rust
let previous_block_hash = if block_number == 0 {
    Bytes32::ZERO
} else {
    system.get_blockhash(block_number - 1)?
};
``` [4](#0-3) 

The proving post-op functions lack this guard entirely. In Rust release mode (the RISC-V proving target), `0u64 - 1` wraps to `u64::MAX`. This corrupted value is hashed into `chain_state_commitment_before.hash()`, which becomes `public_input.state_before` in the `BatchPublicInput`. The final proof public input hash is therefore wrong for the genesis block. [6](#0-5) 

The genesis block is confirmed to be a real, expected scenario — tests assert `header.number == 0` for the first block: [5](#0-4) 

---

### Impact Explanation

The genesis block proof commits to a "before" state with `block_number = u64::MAX` instead of the correct value. This means:

1. **Proof invalidity**: The verifier rejects the proof, making the genesis block unprovable — a **valid-execution unprovability** bug.
2. **Incorrect state commitment**: If the verifier does not independently validate the `block_number` field, it would accept a proof that commits to a wrong state transition, breaking soundness of the ZK proof system for the genesis block.

The `ProofData` struct confirms that `last_block_timestamp` and state root are validated against the chain state commitment, meaning the corrupted `block_number` propagates into the public input hash that the settlement layer verifies. [7](#0-6) 

---

### Likelihood Explanation

The genesis block (block_number = 0) is a necessary and expected input to the proving system. Any deployment of ZKsync OS must prove the genesis block. The bug is deterministically triggered whenever the proving path (`ZKHeaderStructurePostTxOpProvingSingleblockBatch` or `ZKHeaderStructurePostTxOpProvingMultiblockBatch`) is invoked for block_number = 0. No special attacker action is required — this is a normal protocol operation. [8](#0-7) 

---

### Recommendation

Add a guard for `block_number == 0` in both proving post-op functions, analogous to the existing guard in `form_block_header`:

```rust
let chain_state_commitment_before = ChainStateCommitment {
    state_root: state_commitment.root,
    next_free_slot: state_commitment.next_free_slot,
    block_number: metadata.block_number().saturating_sub(1),
    // or: if metadata.block_number() == 0 { 0 } else { metadata.block_number() - 1 }
    last_256_block_hashes_blake: blocks_hasher.finalize().into(),
    last_block_timestamp,
};
```

The correct semantic for the genesis block's "before" commitment block number should be defined by the protocol (likely 0 or a sentinel value), and the guard should match that definition.

---

### Proof of Concept

1. Configure the proving system to prove the genesis block (`block_number = 0`).
2. `post_op` in `ZKHeaderStructurePostTxOpProvingSingleblockBatch` is called.
3. `metadata.block_number()` returns `0`.
4. `metadata.block_number() - 1` underflows to `u64::MAX` in Rust release mode (RISC-V target).
5. `chain_state_commitment_before.block_number = u64::MAX`.
6. `chain_state_commitment_before.hash()` produces a wrong hash.
7. `public_input.state_before` is set to this wrong hash.
8. The final `public_input_hash` is incorrect, and the proof is invalid or commits to a wrong state. [1](#0-0) [2](#0-1)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L54-66)
```rust
    fn post_op(
        system: System<S>,
        block_data: Self::BlockDataKeeper,
        _batch_data: &mut Self::BatchDataKeeper,
        result_keeper: &mut impl ResultKeeperExt<EthereumIOTypesConfig, BlockHeader = Self::BlockHeader>,
    ) -> Result<Self::PostTxLoopOpResult, BootloaderSubsystemError> {
        let block_header = form_block_header(
            &system,
            block_data.transaction_hashes_accumulator.finish().0,
            block_data.block_gas_used,
        )?;
        let block_hash = Bytes32::from(block_header.hash());
        result_keeper.block_sealed(block_header);
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L140-146)
```rust
        let chain_state_commitment_before = ChainStateCommitment {
            state_root: state_commitment.root,
            next_free_slot: state_commitment.next_free_slot,
            block_number: metadata.block_number() - 1,
            last_256_block_hashes_blake: blocks_hasher.finalize().into(),
            last_block_timestamp,
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L200-205)
```rust

        let public_input = BatchPublicInput {
            state_before: chain_state_commitment_before.hash().into(),
            state_after: chain_state_commitment_after.hash().into(),
            batch_output: batch_output.hash().into(),
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L135-141)
```rust
        let chain_state_commitment_before = ChainStateCommitment {
            state_root: state_commitment.root,
            next_free_slot: state_commitment.next_free_slot,
            block_number: metadata.block_number() - 1,
            last_256_block_hashes_blake: blocks_hasher.finalize().into(),
            last_block_timestamp,
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L74-79)
```rust
    let block_number = system.get_block_number();
    let previous_block_hash = if block_number == 0 {
        Bytes32::ZERO
    } else {
        system.get_blockhash(block_number - 1)?
    };
```

**File:** tests/instances/header/src/lib.rs (L19-27)
```rust
    // Check invariants on header for genesis block.
    assert_eq!(header.parent_hash, B256::ZERO);
    assert_eq!(header.ommers_hash, B256::from(EMPTY_OMMER_ROOT_HASH));
    assert_eq!(header.beneficiary, Address::ZERO);
    assert_eq!(header.state_root, B256::ZERO);
    // TODO: enable when this is implemented
    // assert_ne!(header.transactions_root, Bytes32::ZERO);
    // assert_ne!(header.receipts_root, Bytes32::ZERO);
    assert_eq!(header.number, 0);
```

**File:** zk_ee/src/common_structs/proof_data.rs (L8-19)
```rust
///
/// During proof run we need extra data to validate provided inputs against chain state commitment before the block.
///
/// We'll validate reads/apply writes against `state_root_view` and validate that block timestamp is greater than `last_block_timestamp`.
/// At the end we'll calculate chain state commitment before using this fields and other metadata values(block number, hashes) used during execution.
///
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofData<SR: StateRootView<EthereumIOTypesConfig>> {
    pub state_root_view: SR,
    pub last_block_timestamp: u64,
}
```
