### Title
`native_price` and `pubdata_price` Omitted from Block Header and Public Input, Enabling Forward/Proving Divergence — (`basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs`)

---

### Summary

The ZKsync OS block header and batch public input do not commit to `native_price` or `pubdata_price`. These two parameters are the most critical pricing inputs in the system — they govern every transaction's native resource budget and pubdata cost. Because they are absent from the committed block header, the ZK proof does not constrain them, allowing the prover to supply different values than those used during forward execution. This creates a forward/proving divergence: the proven state transition can differ from the sequenced one, and the settlement layer has no way to detect the discrepancy.

---

### Finding Description

The `form_block_header` function in `post_tx_op/mod.rs` carries an explicit `TODO` comment acknowledging the omission:

```rust
// TODO: add pubdata price and native price
``` [1](#0-0) 

The project documentation confirms this is a known gap:

> "The block header should determine the block fully, i.e. include all the inputs needed to execute the block. Currently it misses `gas_per_pubdata` and `native_price`, but we are already working on design and implementation to solve this issue." [2](#0-1) 

The block header feeds into the `ChainStateCommitment`, which is hashed into the batch public input. Neither `native_price` nor `pubdata_price` appear anywhere in `ChainStateCommitment.hash()` or `BatchOutput.hash()`. [3](#0-2) [4](#0-3) 

These two values are read from the oracle at block initialization via `BLOCK_METADATA_QUERY_ID` and stored in `BlockMetadataFromOracle`: [5](#0-4) [6](#0-5) 

During L2 transaction validation, `native_price` and `pubdata_price` are consumed directly from the block-level metadata to compute `native_per_gas` and `native_per_pubdata`: [7](#0-6) 

These ratios determine:
- The native resource budget allocated to each transaction (`nativeLimit = gasLimit × nativePerGas`)
- The native cost charged for every byte of pubdata produced
- Whether a transaction succeeds or is reverted for `OutOfNativeResources` [8](#0-7) 

Because neither value is committed to the public input, the prover is free to supply any `native_price` / `pubdata_price` pair via the oracle without the settlement layer being able to detect the substitution.

---

### Impact Explanation

If the prover supplies `native_price'` ≠ `native_price` or `pubdata_price'` ≠ `pubdata_price`:

1. **Transaction outcome divergence**: Transactions that succeeded during sequencing (barely within their native budget) can be proven as reverted, and vice versa. The proven canonical state on the settlement layer diverges from the state users actually experienced.
2. **Fee and refund manipulation**: `gas_used`, `gas_refunded`, and operator payment are all derived from `native_per_gas` and `native_per_pubdata`. Different pricing inputs produce different token transfers, altering user balances in the proven state.
3. **Undetectable by the settlement layer**: The settlement layer verifies only that the proof is valid for the claimed `(state_before, state_after, batch_output)` triple. Since `native_price` and `pubdata_price` are absent from all three components, any internally consistent execution — regardless of which pricing values were used — produces an accepted proof.

---

### Likelihood Explanation

The entry path is through the prover's oracle inputs, which is explicitly listed as in-scope ("prover/forward execution input"). The prover supplies `BlockMetadataFromOracle` (including `native_price` and `pubdata_price`) to the proving run. Because these values are unconstrained by the public input, a prover that deviates from the sequencer's values — whether intentionally or due to a configuration error — produces a divergent but cryptographically valid proof. No on-chain mechanism prevents or detects this substitution. [9](#0-8) 

---

### Recommendation

1. **Include `native_price` and `pubdata_price` in the block header** so that the block hash commits to them. The `form_block_header` function already has a `TODO` for this.
2. **Propagate them into `ChainStateCommitment` or `BatchOutput`** so the settlement layer can verify that the pricing parameters used during proving match those used during sequencing.
3. Until fixed, treat any proof whose oracle-supplied pricing parameters differ from the sequencer's as invalid at the node level.

---

### Proof of Concept

1. Sequencer executes block with `native_price = 1000`, `pubdata_price = 5000`. Transaction T writes 10 storage slots, uses 95% of its native budget, and **succeeds**. Sequencer publishes state root `S1`.
2. Prover re-executes the same block but supplies `native_price = 500`, `pubdata_price = 50000` via the oracle. Transaction T now exhausts its native budget during pubdata charging and **reverts**. Prover computes state root `S1'` ≠ `S1`.
3. Prover submits a valid ZK proof for the transition `S0 → S1'`. The settlement layer verifies the proof and accepts `S1'` as the new canonical state.
4. The settlement layer has no mechanism to reject this proof: `native_price` and `pubdata_price` appear nowhere in the public input (`ChainStateCommitment`, `BatchOutput`, or `BatchPublicInput`).
5. Users whose transactions succeeded during sequencing find their state changes absent from the canonical chain.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L84-100)
```rust
    let base_fee_per_gas = system.get_eip1559_basefee();
    // TODO: add pubdata price and native price
    let base_fee_per_gas = base_fee_per_gas
        .try_into()
        .map_err(|_| internal_error!("base_fee_per_gas exceeds max u64"))?;

    Ok(BlockHeader::new(
        previous_block_hash,
        beneficiary,
        tx_rolling_hash,
        block_number,
        gas_limit,
        block_gas_used,
        timestamp,
        consensus_random,
        base_fee_per_gas,
    ))
```

**File:** docs/bootloader/bootloader.md (L35-36)
```markdown
The block header should determine the block fully, i.e. include all the inputs needed to execute the block.
Currently it misses `gas_per_pubdata` and `native_price`, but we already working on design and implementation to solve this issue.
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L26-42)
```rust
impl ChainStateCommitment {
    ///
    /// Calculate blake2s hash of chain state commitment.
    ///
    /// We are using proving friendly blake2s because this commitment will be generated and opened during proving,
    /// but we don't need to open it on the settlement layer.
    ///
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = crypto::blake2s::Blake2s256::new();
        hasher.update(self.state_root.as_u8_ref());
        hasher.update(&self.next_free_slot.to_be_bytes());
        hasher.update(&self.block_number.to_be_bytes());
        hasher.update(self.last_256_block_hashes_blake.as_u8_ref());
        hasher.update(&self.last_block_timestamp.to_be_bytes());
        hasher.finalize()
    }
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L82-103)
```rust
impl BatchOutput {
    ///
    /// Calculate keccak256 hash of public input
    ///
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes::<32>());
        hasher.update(&self.first_block_timestamp.to_be_bytes());
        hasher.update(&self.last_block_timestamp.to_be_bytes());
        // Encode DA commitment scheme as U256 BE
        hasher.update([0u8; 31]);
        hasher.update([self.da_commitment_scheme as u8]);
        hasher.update(self.pubdata_commitment.as_u8_ref());
        hasher.update(self.number_of_layer_1_txs.to_be_bytes::<32>());
        hasher.update(self.number_of_layer_2_txs.to_be_bytes::<32>());
        hasher.update(self.priority_operations_hash.as_u8_ref());
        hasher.update(self.l2_logs_tree_root.as_u8_ref());
        hasher.update(self.upgrade_tx_hash.as_u8_ref());
        hasher.update(self.interop_roots_rolling_hash.as_u8_ref());
        hasher.update(self.settlement_layer_chain_id.to_be_bytes::<32>());
        hasher.finalize()
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

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L193-203)
```rust
impl ZkSpecificPricingMetadata for BlockMetadataFromOracle {
    fn get_pubdata_price(&self) -> U256 {
        self.pubdata_price
    }
    fn native_price(&self) -> U256 {
        self.native_price
    }
    fn get_pubdata_limit(&self) -> u64 {
        self.pubdata_limit
    }
}
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L268-301)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L106-139)
```rust
    let pubdata_price = system.get_pubdata_price();
    let native_price = system.get_native_price();

    let gas_price = if transaction.is_service() {
        // Service transactions do not pay gas fees,
        // their gas price is allowed to be < block base fee.
        U256::ZERO
    } else {
        get_gas_price::<S, Config>(
            system,
            transaction.max_fee_per_gas(),
            transaction.max_priority_fee_per_gas(),
        )?
    };

    let native_per_gas = {
        if native_price.is_zero() {
            return Err(internal_error!("Native price cannot be 0").into());
        }

        if cfg!(feature = "resources_for_tester") {
            crate::bootloader::constants::TESTER_NATIVE_PER_GAS
        } else if Config::SIMULATION && gas_price.is_zero() {
            // For simulation, if gas price isn't set, we use base fee
            // for native calculation
            u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price)).ok_or(
                TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive),
            )?
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
    };
```

**File:** docs/double_resource_accounting.md (L37-50)
```markdown
First we define the ratio between EVM gas and native resource as:
  `nativePerGas := gasPrice/nativePrice`
Note: for call simulation we use a constant for it, as gasPrice might be set to 0.

Next we define the limit for the native resource as:
  `nativeLimit := gasLimit * nativePerGas`

Then we process the transaction, charging both Ergs for EE execution and native resource for any kind of computation (EE, bootloader or system work).

If execution doesn't run out of native resources, we first charge for pubdata from native resource.
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```
