### Title
Gateway Stateful Validator Uses Previous Block's L2 Gas Price Instead of Next Block's Price for Admission Threshold — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` computes the admission threshold for a transaction's `max_price_per_unit` using the **previous block's** L2 gas price, but the transaction will be executed at the **next block's** L2 gas price. Because the EIP-1559 fee market adjusts the price every block, the threshold is systematically wrong whenever the price changes, causing the gateway to admit transactions that will be rejected at the batcher, or to reject transactions that would succeed.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the `validate_resource_bounds` method fetches the gas price from the latest committed block and uses it as the reference for the admission threshold:

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

The threshold is then computed as:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
``` [2](#0-1) 

The `GatewayFixedBlockSyncStateClient` always returns the **latest committed block's** gas prices: [3](#0-2) 

Meanwhile, the batcher executes transactions at the **next block's** L2 gas price, which is computed by the EIP-1559 fee market (`calculate_next_l2_gas_price_for_fin`) and can differ from the previous block's price by up to `1/gas_price_max_change_denominator` per block: [4](#0-3) 

The blockifier's `check_fee_bounds` in `perform_pre_validation_stage` enforces the actual block gas price at execution time: [5](#0-4) 

The TODO comment in the source code explicitly acknowledges this discrepancy: `// TODO(Arni): getnext_l2_gas_price from the block header.` [6](#0-5) 

### Impact Explanation

**Scenario A — Price increasing (high congestion):**
The next block's L2 gas price is higher than the previous block's price. The gateway threshold is computed from the lower previous price, so it is too permissive. A transaction with `max_price_per_unit` satisfying `prev_threshold ≤ tx_price < next_threshold` passes gateway admission but is rejected by the batcher's `check_fee_bounds` with `MaxGasPriceTooLow`. The transaction is admitted to the mempool but never sequenced, wasting mempool capacity and causing user confusion.

**Scenario B — Price decreasing (low congestion):**
The next block's L2 gas price is lower than the previous block's price. The gateway threshold is too strict. A transaction with `max_price_per_unit` satisfying `next_threshold ≤ tx_price < prev_threshold` is rejected at the gateway with `GAS_PRICE_TOO_LOW` even though it would succeed at execution time. Valid transactions are incorrectly rejected before sequencing.

Both scenarios match the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The L2 gas price changes every block via the EIP-1559 mechanism. Any block that is not exactly at the gas target causes a price change. In practice, blocks are rarely exactly at the target, so the discrepancy is present in nearly every block. The magnitude is bounded by `1/gas_price_max_change_denominator` per block but accumulates during sustained congestion or low-usage periods. Any unprivileged user submitting a V3 transaction with `AllResources` bounds can trigger either scenario without any special access.

### Recommendation

Replace `previous_block_l2_gas_price` with the computed next block L2 gas price. The sequencer context already exposes `calculate_next_l2_gas_price_for_fin` and the batcher stores `next_l2_gas_price` in the block header (`StorageBlockHeader.next_l2_gas_price`). The gateway should read `next_l2_gas_price` from the latest committed block header and use it as the reference price for the admission threshold, matching the price that will actually be enforced at execution time. [7](#0-6) 

### Proof of Concept

1. Observe the current L2 gas price from the latest committed block: `P_prev`.
2. Compute the next block's expected L2 gas price using the EIP-1559 formula: `P_next > P_prev` (e.g., when the previous block was at 75% capacity with a 50% target).
3. Submit a V3 `AllResources` invoke transaction with `l2_gas.max_price_per_unit = P_prev` (satisfies the gateway threshold `min_gas_price_percentage * P_prev / 100` when percentage ≤ 100).
4. The gateway admits the transaction (`tx_price ≥ threshold`).
5. The batcher builds the next block with `P_next > P_prev` as the block gas price.
6. `check_fee_bounds` in `perform_pre_validation_stage` rejects the transaction with `MaxGasPriceTooLow` because `tx_price = P_prev < P_next = actual_gas_price`.
7. The transaction was admitted to the mempool but is never sequenced — incorrect admission decision.

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-140)
```rust
pub fn calculate_next_base_gas_price(
    price: GasPrice,
    gas_used: GasAmount,
    gas_target: GasAmount,
    min_gas_price: GasPrice,
) -> GasPrice {
    let versioned_constants = VersionedConstants::latest_constants();
    assert!(
        gas_target < versioned_constants.max_block_size,
        "Gas target must be lower than max block size."
    );
    assert!(gas_target.0 > 0, "Gas target must be greater than zero.");
    assert!(
        versioned_constants.gas_price_max_change_denominator > 0,
        "Denominator constant must be greater than zero."
    );

    // If the current price is below the minimum, apply a gradual adjustment and return early.
    // This allows the price to increase by at most 1/MIN_GAS_PRICE_INCREASE_DENOMINATOR per block.
    if price < min_gas_price {
        let max_increase = price.0 / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let adjusted = price.0 + max_increase;
        // Cap at min_gas_price to avoid overshooting
        let adjusted_price = adjusted.min(min_gas_price.0);
        info!(
            "Fee Market: Price {} below minimum gas price {}, adjusted price: {} )",
            price.0, min_gas_price.0, adjusted_price
        );
        return GasPrice(adjusted_price);
    }

    // Use U256 to avoid overflow, as multiplying a u128 by a u64 remains within U256 bounds.
    let gas_delta = U256::from(gas_used.0.abs_diff(gas_target.0));
    let gas_target_u256 = U256::from(gas_target.0);
    let price_u256 = U256::from(price.0);

    // Calculate price change by multiplying first, then dividing. This avoids the precision loss
    // that occurs when dividing before multiplying.
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

    // Sanity check: ensure direction of change is correct
    assert!(
        gas_used > gas_target && adjusted_price_u256 >= price_u256
            || gas_used <= gas_target && adjusted_price_u256 <= price_u256
    );

    // Price should not realistically exceed u128::MAX, bound to avoid theoretical overflow.
    let adjusted_price = u128::try_from(adjusted_price_u256).unwrap_or(u128::MAX);
    GasPrice(max(adjusted_price, min_gas_price.0))
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-476)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
            }
            TransactionInfo::Deprecated(context) => {
                let max_fee = context.max_fee;
                let min_fee = get_fee_by_gas_vector(
                    block_info,
                    minimal_gas_amount_vector,
                    fee_type,
                    tx_context.effective_tip(),
                );
                if max_fee < min_fee {
                    return Err(TransactionPreValidationError::TransactionFeeError(Box::new(
                        TransactionFeeError::MaxFeeTooLow { min_fee, max_fee },
                    )));
                }
            }
        };
        Ok(())
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
