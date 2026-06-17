### Title
Unverified Pricing Fields in Block Metadata Oracle Allow Prover to Manipulate Fee Accounting in Valid ZK Proofs - (File: `basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs`)

---

### Summary

`BlockMetadataFromOracle` is fetched from the oracle at block start and used to compute all transaction fees (`native_per_gas`, `native_per_pubdata`). The pricing fields `native_price`, `pubdata_price`, `eip1559_basefee`, `coinbase`, `gas_limit`, `pubdata_limit`, `mix_hash`, and `blob_fee` are **not included in the ZK public input commitment**. A malicious prover can supply arbitrary values for these fields and still generate a cryptographically valid proof, allowing fee calculations to be manipulated across an entire block.

---

### Finding Description

In `metadata_op.rs`, the bootloader fetches `BlockMetadataFromOracle` from the oracle at block initialization: [1](#0-0) 

The only validation performed is a gas limit upper-bound check. The pricing fields (`native_price`, `pubdata_price`, `eip1559_basefee`) are accepted from the oracle without any constraint or cross-check.

`BlockMetadataFromOracle` carries all of these fields: [2](#0-1) 

These pricing values are then used directly in every transaction's fee computation: [3](#0-2) 

In proving mode, the ZK public input is computed as a hash of `ChainStateCommitment` (before/after) and `BatchOutput`. Inspecting `ChainStateCommitment`: [4](#0-3) 

And `BatchOutput` as hashed for the proof: [5](#0-4) 

Neither structure includes `native_price`, `pubdata_price`, `eip1559_basefee`, `coinbase`, `gas_limit`, `pubdata_limit`, `mix_hash`, or `blob_fee`. Only `chain_id`, `block_number`, `timestamp`, and `block_hashes` from `BlockMetadataFromOracle` are committed to the public input.

The final public input hash is assembled here: [6](#0-5) 

The codebase itself explicitly acknowledges this gap: [7](#0-6) 

In proving mode, the oracle is the `CsrBasedIOOracle` whose responses are provided by the prover via the non-determinism tape. Because `native_price` and `pubdata_price` are not constrained by the proof, a malicious prover can inject arbitrary values and still produce a valid proof.

---

### Impact Explanation

A malicious prover can manipulate the block-level pricing oracle to:

1. **Set `pubdata_price = 0`**: No pubdata fees are charged to any transaction in the block. The formula `native_per_pubdata = pubdata_price / native_price` collapses to zero, so all pubdata is free. L1 data-posting costs are real but are not recovered from users, representing a direct protocol loss.

2. **Set `native_price` to an extreme value**: Alters `native_per_gas = gas_price / native_price` for every transaction, either causing valid transactions to run out of native resources (DoS) or allowing under-priced transactions to execute successfully.

3. **Set `eip1559_basefee = 0`**: Bypasses the base-fee floor check, allowing transactions with any gas price to be included.

The ZK proof remains valid in all cases because these fields are absent from the public input commitment. The settlement layer will accept the proof and finalize the manipulated state transition.

---

### Likelihood Explanation

In proving mode (RISC-V), the oracle is the `CsrBasedIOOracle` whose non-determinism tape is fully controlled by the prover: [8](#0-7) 

The Immunefi scope for ZKsync OS explicitly lists **"prover/forward execution input"** as an attacker type. The ZK proof is supposed to be sound against a malicious prover — if the prover can inject unconstrained oracle data and still produce a valid proof, that is a ZK underconstraint vulnerability, not merely a trusted-operator concern. The `BlockMetadataResponder` in forward mode passes pricing data through without any independent verification: [9](#0-8) 

---

### Recommendation

Include `native_price`, `pubdata_price`, `eip1559_basefee`, `coinbase`, `gas_limit`, `pubdata_limit`, `mix_hash`, and `blob_fee` in either `BatchOutput` or a dedicated block-parameters commitment that is hashed into the ZK public input. This ensures the proof constrains these values and a malicious prover cannot substitute arbitrary pricing data while producing a valid proof. The team has already identified this gap ("we are already working on design and implementation to solve this issue") — the fix should be prioritized before mainnet.

---

### Proof of Concept

1. In proving mode, the prover controls the non-determinism tape fed to `CsrBasedIOOracle`.
2. The prover crafts a `BlockMetadataFromOracle` response to `BLOCK_METADATA_QUERY_ID` with `pubdata_price = U256::ZERO` and `native_price = U256::from(1)`.
3. The bootloader computes `native_per_pubdata = 0 / 1 = 0`, so no pubdata fees are charged to any transaction.
4. Transactions that generate large amounts of pubdata (e.g., many SSTORE operations) execute without paying pubdata fees.
5. The prover generates the ZK proof. The public input hash is computed from `ChainStateCommitment` and `BatchOutput`, neither of which includes `pubdata_price` or `native_price`.
6. The settlement layer verifies the proof successfully and finalizes the state transition. The protocol has absorbed real L1 data-posting costs that were never charged to users.

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs (L18-31)
```rust
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
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L114-132)
```rust
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L106-143)
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

    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L18-24)
```rust
pub struct ChainStateCommitment {
    pub state_root: Bytes32,
    pub next_free_slot: u64,
    pub block_number: u64,
    pub last_256_block_hashes_blake: Bytes32,
    pub last_block_timestamp: u64,
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L185-211)
```rust
        let batch_output = BatchOutput {
            chain_id: U256::from(metadata.chain_id()),
            first_block_timestamp: metadata.block_timestamp(),
            last_block_timestamp: metadata.block_timestamp(),
            da_commitment_scheme: io.da_commitment_scheme.unwrap(),
            pubdata_commitment: da_commitment,
            number_of_layer_1_txs: U256::try_from(number_of_layer_1_txs).unwrap(),
            number_of_layer_2_txs: U256::from(number_of_layer_2_txs),
            priority_operations_hash,
            l2_logs_tree_root: full_l2_to_l1_logs_root,
            upgrade_tx_hash,
            interop_roots_rolling_hash,
            settlement_layer_chain_id,
        };
        logger_log!(logger, "PI calculation: batch output {:?}\n", batch_output,);

        let public_input = BatchPublicInput {
            state_before: chain_state_commitment_before.hash().into(),
            state_after: chain_state_commitment_after.hash().into(),
            batch_output: batch_output.hash().into(),
        };
        logger_log!(
            logger,
            "PI calculation: final batch public input {:?}\n",
            public_input,
        );
        let public_input_hash = public_input.hash().into();
```

**File:** docs/bootloader/bootloader.md (L35-36)
```markdown
The block header should determine the block fully, i.e. include all the inputs needed to execute the block.
Currently it misses `gas_per_pubdata` and `native_price`, but we already working on design and implementation to solve this issue.
```

**File:** proof_running_system/src/system/bootloader.rs (L165-170)
```rust
    // oracle is just a thin proxy
    let oracle = CsrBasedIOOracle::<I>::init();

    logger_log!(L::default(), "Oracle init is complete");

    run_proving_inner::<_, I, L>(oracle)
```

**File:** forward_system/src/run/query_processors/block_metadata.rs (L25-34)
```rust
    fn process_buffered_query(
        &mut self,
        query_id: u32,
        _query: Vec<usize>,
        _memory: &M,
    ) -> Box<dyn ExactSizeIterator<Item = usize> + 'static + Send + Sync> {
        assert!(Self::SUPPORTED_QUERY_IDS.contains(&query_id));

        DynUsizeIterator::from_constructor(self.block_metadata, UsizeSerializable::iter)
    }
```
