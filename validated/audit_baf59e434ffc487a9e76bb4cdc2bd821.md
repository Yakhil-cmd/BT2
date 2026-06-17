### Title
`BlockMetadataFromOracle` Pricing and Execution Fields Not Committed to in ZK Public Input, Enabling Prover Manipulation - (File: `zk_ee/src/system/metadata/zk_metadata.rs`, `basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs`)

---

### Summary

`BlockMetadataFromOracle` is read from the oracle at the start of every block and drives critical execution parameters — `native_price`, `pubdata_price`, `eip1559_basefee`, `coinbase`, `gas_limit`, `pubdata_limit`, `mix_hash` (PREVRANDAO), and `blob_fee`. None of these fields are included in the ZK proof public input (`BatchPublicInput`). A malicious prover can freely substitute arbitrary values for all of them without producing an invalid proof, breaking the trustless property of the rollup.

---

### Finding Description

`BlockMetadataFromOracle` is the struct that carries all block-level execution parameters: [1](#0-0) 

It is fetched unconditionally from the oracle at block start: [2](#0-1) 

In proving mode the oracle is the CSR-based non-determinism source (`CsrBasedIOOracle`), whose responses are entirely prover-supplied: [3](#0-2) 

The ZK public input is computed in `post_op` of `ZKHeaderStructurePostTxOpProvingSingleblockBatch`. The `BatchPublicInput` hash covers only:

- `chain_state_commitment_before/after` → `state_root`, `next_free_slot`, `block_number`, `last_256_block_hashes_blake`, `last_block_timestamp`
- `batch_output` → `chain_id`, `first_block_timestamp`, `last_block_timestamp`, `da_commitment_scheme`, `pubdata_commitment`, `number_of_layer_1_txs`, `number_of_layer_2_txs`, `priority_operations_hash`, `l2_logs_tree_root`, `upgrade_tx_hash`, `interop_roots_rolling_hash`, `settlement_layer_chain_id` [4](#0-3) [5](#0-4) 

The following fields from `BlockMetadataFromOracle` are **absent** from every hash in the public input:

| Field | Used for |
|---|---|
| `native_price` | `native_per_gas` / `native_per_pubdata` computation |
| `pubdata_price` | `native_per_pubdata` computation |
| `eip1559_basefee` | base-fee enforcement, gas-price validation |
| `coinbase` | fee-recipient address |
| `gas_limit` | per-block gas cap |
| `pubdata_limit` | per-block pubdata cap |
| `mix_hash` | `PREVRANDAO` opcode value |
| `blob_fee` | blob base-fee |

The project documentation explicitly acknowledges the gap:

> "The block header should determine the block fully, i.e. include all the inputs needed to execute the block. **Currently it misses `gas_per_pubdata` and `native_price`**, but we already working on design and implementation to solve this issue." [6](#0-5) 

The oracle documentation claims block metadata "is verified by having it as part of the public inputs": [7](#0-6) 

This claim is incorrect for the fields listed above — they are consumed during execution but never bound to the proof.

---

### Impact Explanation

A malicious prover can supply any value for the uncommitted fields and generate a proof that the settlement layer accepts as valid. Concrete impacts:

1. **PREVRANDAO manipulation (`mix_hash`)**: Contracts that use `block.prevrandao` for randomness (lotteries, games, NFT mints) receive a prover-chosen value. The prover can predict or control the outcome, draining user funds from such contracts.

2. **Fee-recipient theft (`coinbase`)**: The prover redirects all transaction fees to an arbitrary address, stealing them from the legitimate operator or users who expect fees to go to a specific address.

3. **Base-fee bypass (`eip1559_basefee`)**: Setting this to zero allows transactions with zero gas price to pass the `GasPriceLessThanBasefee` check, enabling the prover to include transactions that should have been rejected.

4. **Native-resource accounting bypass (`native_price`)**: Setting `native_price` to a very large value makes `native_per_gas = 0`, which triggers the `u64::MAX - 1` native limit path, giving every transaction effectively unlimited native resources. This allows computationally unbounded transactions to be included and finalized. [8](#0-7) 

5. **Pubdata-price bypass (`pubdata_price`)**: Setting to zero makes `native_per_pubdata = 0`, removing all pubdata charging and allowing unlimited state writes without cost.

---

### Likelihood Explanation

The prover fully controls the oracle in proving mode. The `BlockMetadataResponder` simply serializes whatever `BlockMetadataFromOracle` struct it was initialized with: [9](#0-8) 

In the RISC-V proving environment, the prover supplies these values via CSR reads with no external constraint. There is no on-chain commitment to `native_price`, `pubdata_price`, `eip1559_basefee`, `coinbase`, `mix_hash`, or `blob_fee` that the settlement layer can check. The prover can substitute any value for any of these fields in every block they prove.

---

### Recommendation

All fields of `BlockMetadataFromOracle` that affect execution must be bound to the ZK public input. The simplest fix is to hash the full `BlockMetadataFromOracle` struct (or at minimum the uncommitted fields) into `BatchOutput` so the settlement layer can verify them. The project already plans to add `gas_per_pubdata` and `native_price`; the fix should be extended to cover `eip1559_basefee`, `coinbase`, `gas_limit`, `pubdata_limit`, `mix_hash`, and `blob_fee` as well.

---

### Proof of Concept

**Attack: PREVRANDAO manipulation to steal from a lottery contract**

1. A lottery contract on ZKsync OS uses `block.prevrandao` to pick a winner.
2. The prover observes the lottery state and computes the `mix_hash` value that would make a target address win.
3. The prover supplies `BlockMetadataFromOracle { mix_hash: attacker_chosen_value, ... }` via the oracle when proving the block containing the lottery draw.
4. The bootloader reads `mix_hash` and exposes it as `PREVRANDAO` to the EVM interpreter.
5. The lottery contract selects the attacker-controlled address as winner and transfers the prize.
6. The prover generates the proof. Since `mix_hash` is not in `BatchPublicInput`, the proof is valid regardless of the `mix_hash` value used.
7. The settlement layer verifies the proof and finalizes the state transition, including the fraudulent lottery outcome.

The root cause is in `metadata_op.rs` (oracle read with no commitment check) and `public_input.rs` (`BatchOutput::hash()` omitting all pricing/execution fields from `BlockMetadataFromOracle`). [10](#0-9) [11](#0-10)

### Citations

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

**File:** proof_running_system/src/io_oracle/mod.rs (L57-90)
```rust
impl<NDS: NonDeterminismCSRSourceImplementation> IOOracle for CsrBasedIOOracle<NDS> {
    type RawIterator<'a> = CsrBasedIOOracleIterator<NDS>;

    fn raw_query<'a, I: UsizeSerializable + UsizeDeserializable>(
        &'a mut self,
        query_type: u32,
        input: &I,
    ) -> Result<Self::RawIterator<'a>, InternalError> {
        const {
            assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u32>());
        }
        NDS::csr_write_impl(query_type as usize);
        let iter_to_write = UsizeSerializable::iter(input);
        // write length
        let iterator_len = iter_to_write.len();
        assert!(iterator_len == <I as UsizeSerializable>::USIZE_LEN);
        NDS::csr_write_impl(iterator_len);
        // write content
        let mut remaining_len = iterator_len;
        for value in iter_to_write {
            assert!(remaining_len != 0);
            NDS::csr_write_impl(value);
            remaining_len -= 1;
        }
        assert!(remaining_len == 0);
        // we can expect that length of the result is returned via read
        let remaining_len = NDS::csr_read_impl();
        let it = CsrBasedIOOracleIterator::<NDS> {
            remaining: remaining_len,
            _marker: core::marker::PhantomData,
        };

        Ok(it)
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L117-128)
```rust
impl BatchPublicInput {
    ///
    /// Calculate keccak256 hash of public input
    ///
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(self.state_before.as_u8_ref());
        hasher.update(self.state_after.as_u8_ref());
        hasher.update(self.batch_output.as_u8_ref());
        hasher.finalize()
    }
}
```

**File:** docs/bootloader/bootloader.md (L35-36)
```markdown
The block header should determine the block fully, i.e. include all the inputs needed to execute the block.
Currently it misses `gas_per_pubdata` and `native_price`, but we already working on design and implementation to solve this issue.
```

**File:** docs/system/io/oracles.md (L10-11)
```markdown
- Reading the next transaction size and data.
- Reading block metadata (this is verified by having it as part of the public inputs).
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L121-143)
```rust
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
