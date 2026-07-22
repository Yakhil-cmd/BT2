### Title
Gateway Stateful Validator Checks Transaction L2 Gas Price Against Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Wrong Admission Decisions - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `validate_resource_bounds` check compares a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next block** at `next_l2_gas_price`. Because the EIP-1559 mechanism can move the price up or down between blocks, the gateway uses the wrong reference value, causing it to admit transactions that will fail blockifier pre-validation (price rising) or reject transactions that are actually valid (price falling).

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the gateway reads the L2 gas price from the latest committed block:

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
```

The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` from the block header, populating `gas_prices.strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri`. It does **not** read `block_header.next_l2_gas_price`, which is the price computed by `calculate_next_base_gas_price` and stored in the committed block header for use by the **next** block.

The admission threshold is then:

```rust
let threshold = (Ratio::new(min_gas_price_percentage, 100) * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
```

The block header struct (`StorageBlockHeader`) carries both `l2_gas_price` (the price used for the committed block) and `next_l2_gas_price` (the EIP-1559-adjusted price for the next block). The gateway reads only the former.

The own TODO comment at line 229 confirms the intended fix: `// TODO(Arni): getnext_l2_gas_price from the block header.`

**Wrong-admission path (price rising):** When the network is congested (`gas_used > gas_target`), `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` passes the gateway check but fails blockifier `check_fee_bounds` (`MaxGasPriceTooLow`) during `perform_pre_validation_stage`, wasting mempool capacity and batcher cycles.

**Wrong-rejection path (price falling):** When the network is under-utilized (`gas_used < gas_target`), `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price * min_gas_price_percentage/100)` is rejected by the gateway even though it would be perfectly valid for the next block.

### Impact Explanation

- **Wrong admission**: The gateway admits transactions into the mempool that will be rejected by the blockifier at execution time with `InsufficientResourceBounds`. These transactions consume mempool capacity and batcher processing time without ever being included in a block.
- **Wrong rejection**: Valid transactions are rejected at the gateway, denying service to users whose `max_price_per_unit` is correctly set for the upcoming block price.

Both outcomes match: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The EIP-1559 mechanism adjusts the price every block. With `gas_price_max_change_denominator` controlling the per-block change rate, the gap between `l2_gas_price` and `next_l2_gas_price` grows proportionally to how far `gas_used` deviates from `gas_target`. During any sustained period of high or low network load, the two values diverge by a compounding factor each block. With `min_gas_price_percentage = 100` (the default), the threshold equals `l2_gas_price` exactly, so any transaction priced between `l2_gas_price` and `next_l2_gas_price` triggers the wrong-admission path. This is a normal operating condition, not an edge case.

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, read `block_header.next_l2_gas_price` and surface it so `validate_resource_bounds` can use it as the threshold reference. The `BlockInfo` struct (or a gateway-specific wrapper) should carry `next_l2_gas_price` separately from `l2_gas_price`. The admission check should then be:

```rust
let next_block_l2_gas_price = block_header.next_l2_gas_price; // already in fri
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_block_l2_gas_price,
)?;
```

This resolves the TODO at line 229 and aligns the gateway admission decision with the price the blockifier will actually enforce.

### Proof of Concept

1. Observe the latest committed block has `l2_gas_price = P` and `next_l2_gas_price = P'` where `P' > P` (congested network).
2. Submit an `InvokeV3` transaction with `l2_gas.max_price_per_unit = P` (exactly at the current block price).
3. Gateway `validate_resource_bounds` computes `threshold = 100% * P = P`; the transaction passes (`P >= P`).
4. Transaction is admitted to the mempool.
5. Batcher picks the transaction for the next block, which runs at gas price `P'`.
6. Blockifier `check_fee_bounds` → `verify_can_pay_committed_bounds` finds `max_price_per_unit (P) < actual_gas_price (P')` and returns `InsufficientResourceBounds { MaxGasPriceTooLow }`.
7. Transaction fails pre-validation and is dropped from the block, despite having been admitted by the gateway. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** crates/apollo_storage/src/header.rs (L85-90)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
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
