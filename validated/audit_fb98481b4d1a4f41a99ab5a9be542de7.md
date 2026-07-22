### Title
Gateway L2 Gas Price Admission Check Uses Current Block Price Instead of `next_l2_gas_price` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's stateful resource-bounds admission check compares a transaction's `max_price_per_unit` for L2 gas against the **current** block's `l2_gas_price`, but the transaction will be executed in the **next** block at `next_l2_gas_price`. This is the direct Sequencer analog of the VaderReserve bug: a wrong price is used as the conversion/comparison reference, causing the gateway to admit transactions that will fail at execution (when the next block price is higher) and to reject transactions that would succeed (when the next block price is lower).

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the gateway reads the L2 gas price from the latest committed block's `BlockInfo` and uses it as the threshold for admission:

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

The `get_block_info_from_sync_client` implementation populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the price that was used for the **already-committed** block N: [2](#0-1) 

However, the block header also carries a distinct field `next_l2_gas_price`, computed by the EIP-1559 mechanism from block N's gas usage, which is the price that will govern block N+1 — the block the transaction will actually be included in: [3](#0-2) 

The `validate_tx_l2_gas_price_within_threshold` function then enforces:

```
tx.max_price_per_unit >= (min_gas_price_percentage / 100) * block_N.l2_gas_price
``` [4](#0-3) 

But the blockifier's `check_fee_bounds`, which runs at actual execution time, enforces:

```
tx.max_price_per_unit >= block_N+1.l2_gas_price   (i.e., next_l2_gas_price)
``` [5](#0-4) 

The two prices diverge every block via the EIP-1559 `calculate_next_base_gas_price` formula: [6](#0-5) 

The TODO comment in the source code explicitly acknowledges the wrong value is being used: [7](#0-6) 

### Impact Explanation

**Case 1 — Gateway admits transactions that will fail at execution (congested block):**
When block N is congested, `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit` in the range `[threshold_based_on_N, next_l2_gas_price)` passes the gateway check but is rejected by `check_fee_bounds` in the blockifier during execution. The gateway has admitted an invalid transaction, wasting mempool capacity and causing user-visible execution failures.

**Case 2 — Gateway rejects valid transactions (under-utilized block):**
When block N is under-utilized, `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit` in the range `[threshold_based_on_next, threshold_based_on_N)` is rejected by the gateway even though it would succeed at execution. Valid transactions are denied admission.

Both cases match the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block based on gas usage relative to the target. Any block that is not exactly at the gas target produces a `next_l2_gas_price` that differs from the current `l2_gas_price`. This is the normal operating condition of the network. No special attacker capability is required — any user submitting a transaction during a period of changing gas prices will encounter this discrepancy. The `min_gas_price_percentage` config parameter (default non-zero) makes the admission window sensitive to this price difference.

### Recommendation

Replace the read of `block_info.gas_prices.strk_gas_prices.l2_gas_price` with a read of `block_header.next_l2_gas_price` from the raw block header. This requires either:

1. Extending `GatewayFixedBlockStateReader::get_block_info` to also return `next_l2_gas_price`, or
2. Adding a separate `get_next_l2_gas_price` method to `GatewayFixedBlockStateReader` that reads `block_header_without_hash.next_l2_gas_price` directly.

The TODO comment at line 229 already identifies this fix. The `next_l2_gas_price` field is available in `BlockHeaderWithoutHash` and is populated by `GatewayFixedBlockSyncStateClient` from the sync client response. [8](#0-7) 

### Proof of Concept

1. Block N is heavily congested: `l2_gas_price = 100`, `next_l2_gas_price = 112` (12% increase via EIP-1559).
2. `min_gas_price_percentage = 90`, so the gateway threshold = `0.9 * 100 = 90`.
3. User submits a transaction with `max_price_per_unit = 95`.
4. Gateway check: `95 >= 90` → **admitted**.
5. Blockifier `check_fee_bounds` at execution: `95 < 112` → **`MaxGasPriceTooLow`**, transaction fails.
6. The gateway has admitted a transaction that cannot be executed, consuming mempool resources and producing a user-visible failure.

Conversely, if block N is under-utilized: `l2_gas_price = 100`, `next_l2_gas_price = 88`. A transaction with `max_price_per_unit = 89` would pass execution (`89 >= 88`) but is rejected by the gateway (`89 < 90`), denying a valid transaction.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L366-383)
```rust
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

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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
