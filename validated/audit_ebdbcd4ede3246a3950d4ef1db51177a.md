### Title
Gateway Validates L2 Gas Price Against Stale Previous-Block Price Instead of Next-Block Price — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validator checks a transaction's `max_price_per_unit` against the **previous committed block's** L2 gas price, but the batcher executes the transaction against the **next block's** L2 gas price (computed via EIP-1559 from the previous block's gas consumption). A transaction that satisfies the gateway's threshold can fail during block building, causing the gateway to admit transactions that will never be sequenced.

### Finding Description

In `run_validate_entry_point`, the gateway builds a `BlockContext` for blockifier validation by reading the latest committed block's info and bumping only the block number:

```rust
// stateful_transaction_validator.rs:323-330
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
// gas_prices are NOT updated — they remain from block N
let block_context = BlockContext::new(block_info, ...);
``` [1](#0-0) 

The gas prices in this `BlockContext` are therefore block N's prices. The blockifier's `check_fee_bounds` (called inside `perform_pre_validation_stage`) then checks:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() { // error }
``` [2](#0-1) 

...against block N's L2 gas price. The gateway's explicit threshold check in `validate_resource_bounds` also uses block N's price, and the code itself carries a TODO acknowledging the gap:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info().await?
    .gas_prices.strk_gas_prices.l2_gas_price;
``` [3](#0-2) 

The actual next-block L2 gas price is computed by `calculate_next_base_gas_price` (EIP-1559) and stored in the block header as `next_l2_gas_price`: [4](#0-3) [5](#0-4) 

The `GatewayFixedBlockSyncStateClient` reads the block header but only populates `BlockInfo.gas_prices` with the current block's prices; it never reads `next_l2_gas_price`: [6](#0-5) 

The batcher, by contrast, builds its `BlockContext` with the actual next-block prices (the `next_l2_gas_price` field from the committed block header), so the price it enforces during `perform_pre_validation_stage` is higher than what the gateway checked.

### Impact Explanation

A transaction with `max_price_per_unit` satisfying `block_N_price ≤ max_price < block_N+1_price` passes every gateway check and enters the mempool, but is rejected by the batcher's `check_fee_bounds` during block building. The transaction is never included in a block. From the user's perspective the gateway accepted the transaction (no error returned), yet it silently disappears. This matches the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

### Likelihood Explanation

The EIP-1559 formula increases the L2 gas price whenever `gas_used > gas_target`. Under sustained congestion (a normal operating condition), the price rises every block. Any user who sets `max_price_per_unit` equal to the current block's L2 gas price — the most natural choice — will have their transaction admitted by the gateway but rejected by the batcher whenever the next block's price is higher. The gap is bounded by `gas_price_max_change_denominator` (≈ 48 from the versioned constants), giving a maximum per-block increase of roughly 2%, but this is enough to affect every transaction priced at exactly the current market rate during congestion.

### Recommendation

Replace the use of `previous_block_l2_gas_price` in both `validate_resource_bounds` and the `BlockContext` constructed in `run_validate_entry_point` with the `next_l2_gas_price` value stored in the committed block header. Concretely:

1. Extend `GatewayFixedBlockStateReader` (and `GatewayFixedBlockSyncStateClient`) to also return `next_l2_gas_price` from `BlockHeaderWithoutHash`.
2. In `validate_resource_bounds`, compare `tx_l2_gas_price` against `next_l2_gas_price` (resolving the existing TODO).
3. In `run_validate_entry_point`, populate `block_info.gas_prices.strk_gas_prices.l2_gas_price` with `next_l2_gas_price` before constructing the `BlockContext`, so the blockifier's `check_fee_bounds` uses the same price the batcher will enforce.

### Proof of Concept

1. Observe the current L2 gas price from the latest committed block header: `P_N`.
2. Compute the next block's L2 gas price via EIP-1559: `P_N+1 = calculate_next_base_gas_price(P_N, gas_used, gas_target, min_price)`. Under congestion, `P_N+1 > P_N`.
3. Submit an `InvokeV3` transaction with `AllResources` bounds where `l2_gas.max_price_per_unit = P_N`.
4. The gateway's `validate_tx_l2_gas_price_within_threshold` passes (since `P_N ≥ threshold * P_N`).
5. The gateway's blockifier validation passes (since it uses `P_N` in its `BlockContext`).
6. The transaction enters the mempool.
7. The batcher builds block N+1 with `l2_gas_price = P_N+1 > P_N`. When it calls `perform_pre_validation_stage` → `check_fee_bounds`, the check `max_price_per_unit (= P_N) < actual_gas_price (= P_N+1)` triggers `ResourceBoundsError::MaxGasPriceTooLow`, and the transaction is dropped from the block without execution. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-236)
```rust
            // TODO(Arni): getnext_l2_gas_price from the block header.
            let previous_block_l2_gas_price = self
                .gateway_fixed_block_state_reader
                .get_block_info()
                .await?
                .gas_prices
                .strk_gas_prices
                .l2_gas_price;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-330)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
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

**File:** crates/apollo_starknet_client/src/reader/objects/block.rs (L296-300)
```rust
    pub fn next_l2_gas_price(&self) -> GasPrice {
        match self {
            Block::PostV0_13_1(block) => block.next_l2_gas_price,
        }
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
