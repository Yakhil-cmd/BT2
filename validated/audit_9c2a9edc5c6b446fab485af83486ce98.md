### Title
Gateway L2 Gas Price Threshold Uses Stale Previous-Block Price Instead of `next_l2_gas_price` - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's L2 gas price against the **current block's** `l2_gas_price` from storage, but the transaction will execute in the **next block** whose price is `next_l2_gas_price` (computed via EIP-1559 from the current block's gas usage). The code itself contains a `TODO` acknowledging this: `// TODO(Arni): getnext_l2_gas_price from the block header.` This is the direct analog of the GMX bug: using a stored/stale accumulator instead of the forward-projected value.

### Finding Description

In `validate_resource_bounds`:

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

The threshold check compares `tx.l2_gas.max_price_per_unit` against `previous_block_l2_gas_price * min_gas_price_percentage / 100`: [2](#0-1) 

The L2 gas price is EIP-1559 dynamic. After each block is finalized, `calculate_next_l2_gas_price_for_fin` computes the price for the **next** block and stores it in `BlockHeaderWithoutHash::next_l2_gas_price`: [3](#0-2) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs `BlockInfo` from the block header but only maps `l2_gas_price` (the price used for the **current** block), not `next_l2_gas_price`: [4](#0-3) 

The `calculate_next_base_gas_price` function shows the price can change significantly each block (up/down by `gas_delta / (gas_target * denominator)`): [5](#0-4) 

### Impact Explanation

Two incorrect admission outcomes arise:

1. **Valid transactions rejected** (price decreasing): When the network is below target, `next_l2_gas_price < current_l2_gas_price`. A transaction with `max_price_per_unit` in the range `[next * threshold, current * threshold)` is valid for the next block but is rejected at the gateway with `GAS_PRICE_TOO_LOW`. This is a **false rejection** of a valid transaction — matching the "rejects valid transactions before sequencing" High impact.

2. **Invalid transactions admitted** (price increasing): When the network is above target, `next_l2_gas_price > current_l2_gas_price`. A transaction with `max_price_per_unit` in the range `[current * threshold, next * threshold)` passes the gateway check but will fail `check_fee_bounds` in `perform_pre_validation_stage` at blockifier execution time, wasting mempool and batcher resources. [6](#0-5) 

### Likelihood Explanation

The L2 gas price changes every block. During any sustained period of above-target or below-target block utilization (normal operating conditions), the `next_l2_gas_price` diverges from `current_l2_gas_price`. Any user submitting a V3 (`AllResources`) transaction during such a period with a gas price in the divergence band triggers the incorrect admission decision. No special privileges are required.

### Recommendation

In `validate_resource_bounds`, read `next_l2_gas_price` from the block header instead of `l2_gas_price`. This requires:

1. Exposing `next_l2_gas_price` from `GatewayFixedBlockStateReader::get_block_info` (it is already stored in `BlockHeaderWithoutHash::next_l2_gas_price`).
2. Passing `next_l2_gas_price` to `validate_tx_l2_gas_price_within_threshold` instead of `previous_block_l2_gas_price`.

The existing TODO comment at line 229 already identifies this fix: `// TODO(Arni): getnext_l2_gas_price from the block header.` [7](#0-6) 

### Proof of Concept

1. Observe the current block's L2 gas price `P_curr` from the latest block header.
2. Compute `P_next = calculate_next_base_gas_price(P_curr, gas_used, gas_target, min)` — this is the price for the next block.
3. Assume `P_next < P_curr` (below-target block, price decreasing) and `min_gas_price_percentage = 50`.
4. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P_next` (valid for the next block, since `P_next >= P_next * 50%`).
5. The gateway reads `P_curr` and computes `threshold = P_curr * 50%`. Since `P_next < P_curr`, it is possible that `P_next < threshold`, causing the gateway to return `GAS_PRICE_TOO_LOW` and reject the transaction — even though the transaction would have been accepted and executed correctly in the next block.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-240)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-412)
```rust
        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
            timestamp: BlockTimestamp(init.timestamp),
            l1_da_mode: init.l1_da_mode,
            fee_proposal_fri: init.fee_proposal_fri,
            // TODO(guy.f): Figure out where/if to get the values below from and fill them.
            ..Default::default()
        };
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
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
