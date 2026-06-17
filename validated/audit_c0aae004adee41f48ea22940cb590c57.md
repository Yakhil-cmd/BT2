### Title
Missing `block_number > 0` Validation in Oracle-Provided Block Metadata Causes Integer Underflow in Proving-Mode Public Input Computation — (`File: basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs` / `post_tx_op_proving_multiblock_batch.rs`)

---

### Summary

`BlockMetadataFromOracle` is deserialized from untrusted oracle input without validating that `block_number > 0`. In proving mode, the code unconditionally computes `metadata.block_number() - 1` to form `chain_state_commitment_before`. If `block_number == 0`, this subtraction wraps to `u64::MAX` (release mode) or panics (debug mode), corrupting the `chain_state_commitment_before` field that is hashed into the batch public input.

---

### Finding Description

`BlockMetadataFromOracle` is populated entirely from oracle data via `UsizeDeserializable::from_iter`. The deserialization performs no semantic validation on any field: [1](#0-0) 

The only post-deserialization check in `metadata_op` is an upper-bound guard on `gas_limit`: [2](#0-1) 

`native_price` is validated later at transaction-validation time (checked `!= 0`), but `block_number` is never validated to be `> 0` anywhere in the pipeline. [3](#0-2) 

In both proving-mode post-tx operations, `block_number - 1` is computed without a prior bounds check: [4](#0-3) [5](#0-4) 

The resulting `chain_state_commitment_before` (with `block_number = u64::MAX`) is then hashed into the batch public input: [6](#0-5) 

The `block_number` field is a security-critical component of the public input, as documented: [7](#0-6) 

---

### Impact Explanation

**Vulnerability class**: Oracle IO mismatch / valid-execution unprovability.

A prover supplying `block_number = 0` causes `chain_state_commitment_before.block_number` to silently wrap to `u64::MAX` in release builds. This corrupts the `BatchPublicInput` hash. The resulting proof either:

1. Is rejected by the settlement layer (because the public input does not match the expected block number), causing a denial-of-service on the proving pipeline for that batch; or
2. In a scenario where the settlement layer has a separate validation gap, could be used to assert a fraudulent chain-state transition anchored at block `u64::MAX`.

The oracle documentation explicitly states that oracle responses are untrusted and **must** be validated by calling code: [8](#0-7) [9](#0-8) 

---

### Likelihood Explanation

The entry point is the prover/forward execution input, which is explicitly listed as an in-scope attacker surface. The `BlockMetadataFromOracle` struct derives `Default` (giving `block_number = 0`) and its `from_iter` imposes no lower-bound constraint. A malicious or buggy prover can trivially supply `block_number = 0`. The `Chain::next_block_number()` helper also returns `0` for the very first block when `previous_block_number` is `None`, meaning this path is reachable even without a malicious actor in certain initialization sequences. [10](#0-9) [11](#0-10) 

---

### Recommendation

Add a lower-bound validation for `block_number` (and analogously for `timestamp`) immediately after oracle deserialization in `metadata_op`, mirroring the existing `gas_limit` upper-bound check:

```rust
// In basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs
if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
    || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
{
    return Err(internal_error!("block or tx gas limit is too high"));
}
// ADD:
if metadata.block_number() == 0 {
    return Err(internal_error!("block number must be > 0"));
}
if metadata.block_timestamp() == 0 {
    return Err(internal_error!("block timestamp must be > 0"));
}
```

Alternatively, use `checked_sub(1).ok_or(...)` at the point of use in both proving-mode post-tx operations to convert the underflow into a recoverable error rather than a silent wrap or panic.

---

### Proof of Concept

1. Construct a `BlockMetadataFromOracle` with `block_number = 0` (trivially achievable via `Default::default()` or by serializing a zero value into the oracle stream).
2. Feed it through `oracle.query_with_empty_input(BLOCK_METADATA_QUERY_ID)` in proving mode.
3. `metadata_op` accepts it (only `gas_limit` is checked).
4. In `post_op` of `ZKHeaderStructurePostTxOpProvingSingleblockBatch`, the line `block_number: metadata.block_number() - 1` evaluates to `0u64 - 1`.
5. In a release build this wraps to `u64::MAX`; `chain_state_commitment_before.block_number = u64::MAX`.
6. `chain_state_commitment_before.hash()` produces a value inconsistent with any legitimate chain state, corrupting `BatchPublicInput` and causing the resulting proof to be invalid. [12](#0-11) [13](#0-12) [14](#0-13)

### Citations

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L112-132)
```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BlockMetadataFromOracle {
    // Chain id is temporarily also added here (so that it can be easily passed from the oracle)
    // long term, we have to decide whether we want to keep it here, or add a separate oracle
    // type that would return some 'chain' specific metadata (as this class is supposed to hold block metadata only).
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hashes: BlockHashes,
    pub timestamp: u64,
    pub eip1559_basefee: U256,
    pub pubdata_price: U256,
    pub native_price: U256,
    pub coinbase: B160,
    pub gas_limit: u64,
    pub pubdata_limit: u64,
    /// Source of randomness, currently holds the value
    /// of prevRandao.
    pub mix_hash: U256,
    pub blob_fee: U256,
}
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L268-302)
```rust
impl UsizeDeserializable for BlockMetadataFromOracle {
    const USIZE_LEN: usize = <Self as UsizeSerializable>::USIZE_LEN;

    fn from_iter(src: &mut impl ExactSizeIterator<Item = usize>) -> Result<Self, InternalError> {
        let eip1559_basefee = UsizeDeserializable::from_iter(src)?;
        let pubdata_price = UsizeDeserializable::from_iter(src)?;
        let native_price = UsizeDeserializable::from_iter(src)?;
        let block_number = UsizeDeserializable::from_iter(src)?;
        let timestamp = UsizeDeserializable::from_iter(src)?;
        let chain_id = UsizeDeserializable::from_iter(src)?;
        let gas_limit = UsizeDeserializable::from_iter(src)?;
        let pubdata_limit = UsizeDeserializable::from_iter(src)?;
        let coinbase = UsizeDeserializable::from_iter(src)?;
        let block_hashes = UsizeDeserializable::from_iter(src)?;
        let mix_hash = UsizeDeserializable::from_iter(src)?;
        let blob_fee = UsizeDeserializable::from_iter(src)?;

        let new = Self {
            eip1559_basefee,
            pubdata_price,
            native_price,
            block_number,
            timestamp,
            chain_id,
            gas_limit,
            pubdata_limit,
            coinbase,
            block_hashes,
            mix_hash,
            blob_fee,
        };

        Ok(new)
    }
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs (L14-34)
```rust
    fn metadata_op<Config: BasicBootloaderExecutionConfig>(
        oracle: &mut impl IOOracle,
        _allocator: S::Allocator,
    ) -> Result<<S as SystemTypes>::Metadata, InternalError> {
        let block_level_metadata: BlockMetadataFromOracle =
            oracle.query_with_empty_input(BLOCK_METADATA_QUERY_ID)?;

        let metadata = ZkMetadata {
            tx_level: TxLevelMetadata::default(),
            block_level: block_level_metadata,
            _marker: core::marker::PhantomData,
        };

        if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
            || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
        {
            return Err(internal_error!("block or tx gas limit is too high"));
        }

        Ok(metadata)
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L121-124)
```rust
    let native_per_gas = {
        if native_price.is_zero() {
            return Err(internal_error!("Native price cannot be 0").into());
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L120-146)
```rust
        let (mut state_commitment, last_block_timestamp) = {
            let proof_data: ProofData<FlatStorageCommitment<TREE_HEIGHT>> =
                ZKProofDataQuery::get(&mut io.oracle, &())
                    .expect("must get proof data from oracle");
            (proof_data.state_root_view, proof_data.last_block_timestamp)
        };

        logger_log!(
            logger,
            "Initial state commitment is {:?}\n",
            &state_commitment
        );
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);

        // chain state commitment before
        let mut blocks_hasher = Blake2s256::new();
        for block_hash in metadata.block_level.block_hashes.0.iter() {
            blocks_hasher.update(&block_hash.to_be_bytes::<32>());
        }
        let chain_state_commitment_before = ChainStateCommitment {
            state_root: state_commitment.root,
            next_free_slot: state_commitment.next_free_slot,
            block_number: metadata.block_number() - 1,
            last_256_block_hashes_blake: blocks_hasher.finalize().into(),
            last_block_timestamp,
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L201-205)
```rust
        let public_input = BatchPublicInput {
            state_before: chain_state_commitment_before.hash().into(),
            state_after: chain_state_commitment_after.hash().into(),
            batch_output: batch_output.hash().into(),
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L115-141)
```rust
        let (mut state_commitment, last_block_timestamp) = {
            let proof_data: ProofData<FlatStorageCommitment<TREE_HEIGHT>> =
                ZKProofDataQuery::get(&mut io.oracle, &())
                    .expect("must get proof data from oracle");
            (proof_data.state_root_view, proof_data.last_block_timestamp)
        };

        logger_log!(
            logger,
            "Initial state commitment is {:?}\n",
            &state_commitment
        );
        // validate that timestamp didn't decrease
        assert!(metadata.block_timestamp() >= last_block_timestamp);

        // chain state commitment before
        let mut blocks_hasher = Blake2s256::new();
        for block_hash in metadata.block_level.block_hashes.0.iter() {
            blocks_hasher.update(&block_hash.to_be_bytes::<32>());
        }
        let chain_state_commitment_before = ChainStateCommitment {
            state_root: state_commitment.root,
            next_free_slot: state_commitment.next_free_slot,
            block_number: metadata.block_number() - 1,
            last_256_block_hashes_blake: blocks_hasher.finalize().into(),
            last_block_timestamp,
        };
```

**File:** docs/l1_integration.md (L43-49)
```markdown
- `chain_state_commitment_before` is `blake2s` hash of(concatenation):
  - `state_root`
  - `next_free_slot`
  - `block_number`
  - `last_256_block_hashes_blake`
  - `last_block_timestamp`
    before the block(s).
```

**File:** zk_ee/src/oracle/mod.rs (L13-16)
```rust
//! # Security Model
//!
//! **Critical**: Oracle responses are treated as **untrusted input**. The oracle system does not validate data authenticity or correctness. All oracle
//! responses MUST be validated by the calling code before use.
```

**File:** docs/system/io/oracles.md (L80-87)
```markdown
### Security Considerations

**Important**: Oracle responses are non-deterministic and MUST be treated as untrusted input. All responses should be:

- Treated as opaque byte arrays, or
- Validated against additional constraints during deserialization or usage

Query ID uniqueness is not enforced on the caller side, so proper validation is critical for system security.
```

**File:** tests/rig/src/chain.rs (L351-353)
```rust
    pub fn next_block_number(&self) -> u64 {
        self.previous_block_number.map(|n| n + 1).unwrap_or(0)
    }
```
