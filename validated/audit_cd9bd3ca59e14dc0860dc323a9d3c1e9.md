### Title
Gateway L2 Gas Price Validation Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Incorrect Admission/Rejection of Transactions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check validates a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the block that will actually execute the transaction uses `next_l2_gas_price` (the EIP-1559-adjusted price stored in the same block header). Because these two values diverge by up to ~1% per block, the gateway systematically admits transactions that will fail at execution time (when the network is congested) and rejects transactions that would have succeeded (when the network is under-utilized). A developer TODO in the source code explicitly acknowledges the wrong field is being read.

---

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` fetches the latest block's `BlockInfo` and reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` as the reference price:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,
)?;
``` [1](#0-0) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` from the block header but only copies `l2_gas_price`, silently discarding `next_l2_gas_price`:

```rust
let block_info = BlockInfo {
    ...
    gas_prices: GasPrices {
        strk_gas_prices: GasPriceVector {
            ...
            l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
        },
    },
    ...
};
``` [2](#0-1) 

The `BlockHeaderWithoutHash` struct carries **both** fields:

```rust
pub struct BlockHeaderWithoutHash {
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,   // ← the price for the NEXT block
    ...
}
``` [3](#0-2) 

`next_l2_gas_price` is the EIP-1559 fee-market output stored in every block header and used by the batcher when building the next block: [4](#0-3) 

The fee market can move the price by up to ~1% per block (higher under congestion, lower under low utilization): [5](#0-4) 

The same stale `BlockInfo` is also passed into `run_validate_entry_point`, which increments only the block number but leaves the gas prices unchanged, so the blockifier's `check_fee_bounds` inside the gateway also uses the wrong price: [6](#0-5) 

---

### Impact Explanation

**Accepts invalid transactions (congested network):** When `next_l2_gas_price > l2_gas_price` (block is above the gas target), the gateway's threshold is computed from the lower stale price. A transaction whose `max_price_per_unit` satisfies `threshold × l2_gas_price ≤ tx_price < threshold × next_l2_gas_price` passes gateway admission and enters the mempool, but will fail `check_fee_bounds` at execution time in the batcher because the actual block gas price is `next_l2_gas_price`.

**Rejects valid transactions (under-utilized network):** When `next_l2_gas_price < l2_gas_price` (block is below the gas target), the gateway's threshold is computed from the higher stale price. A transaction whose `max_price_per_unit` satisfies `threshold × next_l2_gas_price ≤ tx_price < threshold × l2_gas_price` is rejected at the gateway even though it would have passed execution.

Both outcomes match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The fee market adjusts `next_l2_gas_price` every block. Under normal operation the divergence is small (~0.3–1% per block), but it is **always present** whenever the block is not exactly at the gas target. The condition is unprivileged: any user submitting a transaction with a gas price in the gap between the two values triggers the incorrect admission or rejection. No special access is required.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, expose `next_l2_gas_price` from the block header (it is already stored in `BlockHeaderWithoutHash::next_l2_gas_price`). Extend the `GatewayFixedBlockStateReader` trait (or add a separate accessor) to return this value, and replace the `l2_gas_price` read in `validate_resource_bounds` with `next_l2_gas_price`. The TODO comment at line 229 already identifies the correct fix:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [7](#0-6) 

Similarly, the `BlockInfo` constructed in `run_validate_entry_point` should use `next_l2_gas_price` for the L2 gas price field so that the blockifier's `check_fee_bounds` at the gateway is consistent with what the batcher will enforce.

---

### Proof of Concept

1. Observe the latest finalized block has `l2_gas_price = P` and `next_l2_gas_price = P' = P × (1 + δ)` where `δ ≈ 0.01` (1% increase due to high congestion).
2. Submit an invoke V3 transaction with `l2_gas.max_price_per_unit = P` (exactly equal to the stale price, satisfying `threshold × P` with `min_gas_price_percentage = 100`).
3. The gateway's `validate_tx_l2_gas_price_within_threshold` computes `threshold = 1.0 × P` and accepts the transaction (`P ≥ P`). [8](#0-7) 
4. The transaction enters the mempool.
5. The batcher builds the next block with gas price `P'`. When `perform_pre_validation_stage` runs `check_fee_bounds`, it finds `tx.max_price_per_unit = P < P' = actual_gas_price` and the transaction fails with `MaxGasPriceTooLow`. [9](#0-8) 
6. The transaction is reverted or dropped, despite having passed gateway admission — confirming the gateway admitted an invalid transaction.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L223-243)
```rust
    async fn validate_resource_bounds(
        &self,
        executable_tx: &ExecutableTransaction,
    ) -> StatefulTransactionValidatorResult<()> {
        // Skip this validation during the systems bootstrap phase.
        if self.config.validate_resource_bounds {
            // TODO(Arni): getnext_l2_gas_price from the block header.
            let previous_block_l2_gas_price = self
                .gateway_fixed_block_state_reader
                .get_block_info()
                .await?
                .gas_prices
                .strk_gas_prices
                .l2_gas_price;
            self.validate_tx_l2_gas_price_within_threshold(
                executable_tx.resource_bounds(),
                previous_block_l2_gas_price,
            )?;
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
        match tx_resource_bounds {
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
                    return Err(StarknetError {
                        // We didn't have this kind of an error.
                        code: StarknetErrorCode::UnknownErrorCode(
                            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
                        ),
                        message: format!(
                            "Transaction L2 gas price {tx_l2_gas_price} is below the required \
                             threshold {threshold}.",
                        ),
                    });
                }
            }
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L30-57)
```rust
    async fn get_block_info_from_sync_client(&self) -> StarknetResult<BlockInfo> {
        let block = self.state_sync_client.get_block(self.block_number).await.map_err(|e| {
            StarknetError::internal_with_logging("Failed to get latest block info", e)
        })?;

        let block_header = block.block_header_without_hash;
        let block_info = BlockInfo {
            block_number: block_header.block_number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_wei.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_wei.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_wei.try_into()?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
            },
            use_kzg_da: block_header.l1_da_mode.is_use_kzg_da(),
            starknet_version: block_header.starknet_version,
        };

        Ok(block_info)
    }
```

**File:** crates/starknet_api/src/block.rs (L231-248)
```rust
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct BlockHeaderWithoutHash {
    pub parent_hash: BlockHash,
    pub block_number: BlockNumber,
    pub l1_gas_price: GasPricePerToken,
    pub l1_data_gas_price: GasPricePerToken,
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
    pub state_root: GlobalRoot,
    pub sequencer: SequencerContractAddress,
    pub timestamp: BlockTimestamp,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub starknet_version: StarknetVersion,
    // TODO(AndrewL): Add this field into the block hash.
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
}
```

**File:** crates/apollo_storage/src/header.rs (L71-114)
```rust
/// Storage representation of a Starknet block header.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageBlockHeader {
    /// The hash of this block.
    pub block_hash: BlockHash,
    /// The hash of this block's parent.
    pub parent_hash: BlockHash,
    /// The number of this block.
    pub block_number: BlockNumber,
    /// The L1 gas price per token.
    pub l1_gas_price: GasPricePerToken,
    /// The L1 data gas price per token.
    pub l1_data_gas_price: GasPricePerToken,
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
    pub state_root: GlobalRoot,
    /// The sequencer address that created this block.
    pub sequencer: SequencerContractAddress,
    /// The timestamp of this block.
    pub timestamp: BlockTimestamp,
    /// The L1 data availability mode.
    pub l1_da_mode: L1DataAvailabilityMode,
    /// The state diff commitment, if available.
    pub state_diff_commitment: Option<StateDiffCommitment>,
    /// The transaction commitment, if available.
    pub transaction_commitment: Option<TransactionCommitment>,
    /// The event commitment, if available.
    pub event_commitment: Option<EventCommitment>,
    /// The receipt commitment, if available.
    pub receipt_commitment: Option<ReceiptCommitment>,
    /// The length of the state diff, if available.
    pub state_diff_length: Option<usize>,
    /// The number of transactions in this block.
    pub n_transactions: usize,
    /// The number of events in this block.
    pub n_events: usize,
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
}
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L15-21)
```rust
// Denominator for the maximum gas price increase per block when price is below minimum.
// This controls how quickly the gas price can rise towards the minimum.
//
// With a denominator of 333: Each block can increase by at most 0.3% of the current price, to
// double the price takes approximately 230 blocks (at 2.6 seconds per block), this means doubling
// in approximately 10 minutes.
const MIN_GAS_PRICE_INCREASE_DENOMINATOR: u128 = 333;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
```
