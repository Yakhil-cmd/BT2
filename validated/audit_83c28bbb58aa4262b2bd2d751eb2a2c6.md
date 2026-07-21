### Title
Gateway Resource-Bounds Admission Uses Previous Block's L2 Gas Price Instead of Next Block's Actual Price — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **previous block's** L2 gas price, but the transaction will be executed in the **next block** whose L2 gas price is computed by the EIP-1559 formula and may differ. This is the direct sequencer analog of the Zivoe bug: a fixed reference value (previous block price) is assumed to represent the actual execution context (next block price), causing the gateway to make systematically wrong admission decisions.

### Finding Description

In `validate_resource_bounds`, the gateway fetches the previous block's L2 gas price and uses it as the threshold:

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

The threshold is `min_gas_price_percentage% × P_prev`. The TODO comment explicitly acknowledges the wrong reference is being used.

In `run_validate_entry_point`, the blockifier validation also uses the previous block's gas prices — only the block number is incremented, not the gas prices:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
``` [2](#0-1) 

However, when the batcher actually executes the transaction, it uses the **real next block's gas prices** (`P_next`), computed by the EIP-1559 formula in `calculate_next_base_gas_price`: [3](#0-2) 

The batcher's `get_block_info` reads the committed block header's gas prices, which are the actual prices for that block: [4](#0-3) 

The blockifier's `check_fee_bounds` in `perform_pre_validation_stage` then enforces `resource_bounds.max_price_per_unit >= actual_gas_price` using `P_next`: [5](#0-4) 

### Impact Explanation

Two systematic wrong-admission scenarios arise in every block where the EIP-1559 price changes:

**Case A — price rises (high gas usage in previous block, P_next > P_prev):**  
A transaction with `threshold_prev ≤ max_price_per_unit < threshold_next` passes gateway admission but fails during batcher execution with `MaxGasPriceTooLow`. The gateway **accepts an invalid transaction**.

**Case B — price falls (low gas usage in previous block, P_next < P_prev):**  
A transaction with `threshold_next ≤ max_price_per_unit < threshold_prev` is rejected by the gateway even though it would succeed during execution. The gateway **rejects a valid transaction**.

Both cases occur in normal EIP-1559 operation. The magnitude of the discrepancy per block is bounded by `gas_price_max_change_denominator`, but it is non-zero whenever gas usage deviates from the target.

### Likelihood Explanation

This triggers on every block where L2 gas usage differs from `gas_target` — i.e., in virtually every block under real load. No special attacker action is required; any user submitting a V3 transaction with `AllResources` bounds when `validate_resource_bounds = true` is affected. The condition is unprivileged and structurally guaranteed by the EIP-1559 fee market.

### Recommendation

Replace `previous_block_l2_gas_price` in `validate_resource_bounds` with the **next block's** L2 gas price. The TODO comment at line 229 already identifies this fix. The next block's L2 gas price is available from the block header's `next_l2_gas_price` field (as used in `try_sync` in the consensus orchestrator) or can be computed from the previous block's gas usage via `calculate_next_l2_gas_price_for_fin`. The same correction should be applied to `run_validate_entry_point` so that blockifier gateway-validation uses the same price as batcher execution.

### Proof of Concept

1. Observe previous block with high gas usage: `P_prev = 100`, `P_next = 101` (EIP-1559 increase), `min_gas_price_percentage = 100`.
2. Submit a V3 `AllResources` transaction with `l2_gas.max_price_per_unit = 100`.
3. Gateway calls `validate_resource_bounds`: threshold = `100% × 100 = 100`; `100 >= 100` → **admitted**.
4. Batcher executes the transaction with `P_next = 101`; blockifier `check_fee_bounds`: `100 < 101` → **`MaxGasPriceTooLow`, transaction fails**.
5. The gateway admitted a transaction that was guaranteed to fail during execution, wasting block space and charging the user a revert fee. [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-324)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
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

**File:** crates/apollo_batcher/src/batcher.rs (L699-717)
```rust
        Ok(BlockInfo {
            block_number: header.block_number,
            block_timestamp: header.timestamp,
            sequencer_address: header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_wei)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_wei)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_wei)?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_fri)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_fri)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_fri)?,
                },
            },
            use_kzg_da: header.l1_da_mode.is_use_kzg_da(),
            starknet_version: header.starknet_version,
        })
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-57)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}

impl GatewayFixedBlockSyncStateClient {
    pub fn new(state_sync_client: SharedStateSyncClient, block_number: BlockNumber) -> Self {
        Self { state_sync_client, block_number, block_info_cache: OnceCell::new() }
    }

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
