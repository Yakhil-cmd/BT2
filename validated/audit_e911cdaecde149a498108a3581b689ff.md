### Title
Gateway L2 Gas Price Admission Check Uses Stale Previous-Block Price Instead of `next_l2_gas_price` - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` validates a transaction's `max_price_per_unit` against the **current (previous) block's** L2 gas price rather than the `next_l2_gas_price` stored in that same block header. Because the L2 gas price follows an EIP-1559-like adjustment per block, the price used for admission is systematically stale. During congestion, when the price is rising, transactions whose gas price is below the threshold for the next block pass gateway admission and enter the mempool, only to fail at blockifier execution.

### Finding Description

`validate_resource_bounds` reads `block_header.l2_gas_price.price_in_fri` (the price **of** the last committed block) as the reference for the threshold check:

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

The in-code TODO explicitly acknowledges the bug: `// TODO(Arni): getnext_l2_gas_price from the block header.`

The block header already carries a distinct `next_l2_gas_price` field — the price that will govern the **next** block — but `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` discards it and only maps `block_header.l2_gas_price.price_in_fri` into the returned `BlockInfo`:

```rust
strk_gas_prices: GasPriceVector {
    ...
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

The `next_l2_gas_price` field is present in the block header and in storage: [3](#0-2) 

The L2 gas price is updated every block via `calculate_next_base_gas_price` (EIP-1559 style). When the block is above the gas target, the price rises by up to `1/gas_price_max_change_denominator` per block: [4](#0-3) 

The `next_l2_gas_price` for block N is computed from block N's gas usage and stored in block N's header. It is the price that will be enforced when block N+1 is executed. The gateway should validate against this value, not against block N's own `l2_gas_price`.

The threshold check in `validate_tx_l2_gas_price_within_threshold` is:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
``` [5](#0-4) 

With a stale (lower) reference price, the computed `threshold` is lower than it should be, so transactions with a `max_price_per_unit` that is above the stale threshold but below the correct next-block threshold are admitted.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

A transaction admitted with a gas price below the actual next-block threshold will fail at blockifier execution with `InsufficientResourceBounds` / `MaxGasPriceTooLow`. This means:

1. The mempool fills with transactions that cannot be included in the next block.
2. The batcher wastes execution cycles attempting and reverting these transactions.
3. Under sustained congestion (rapidly rising price), an attacker can flood the mempool with zero-cost-to-submit transactions that are guaranteed to fail, degrading sequencer throughput.

### Likelihood Explanation

The L2 gas price rises whenever a block exceeds the gas target. During any period of moderate-to-high network activity the price will be increasing block-over-block, making the stale reference price consistently lower than the correct one. The gap grows with congestion. No special privilege is required; any user can submit a transaction with a gas price calibrated to the stale threshold.

### Recommendation

Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (or a separate accessor) and use it in `validate_resource_bounds`:

1. Add `next_l2_gas_price: GasPrice` to the data returned by `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, reading `block_header.next_l2_gas_price`.
2. In `validate_resource_bounds`, replace `previous_block_l2_gas_price` with the `next_l2_gas_price` value from the same block header.

This directly resolves the acknowledged TODO and aligns the admission check with the price that will actually be enforced at execution time.

### Proof of Concept

1. The network is under load; block N has `l2_gas_price = 100 fri` and `next_l2_gas_price = 112 fri` (12 % increase due to congestion). `min_gas_price_percentage = 50`.
2. Correct admission threshold for block N+1: `112 * 50 / 100 = 56 fri`.
3. Stale threshold used by the gateway: `100 * 50 / 100 = 50 fri`.
4. Attacker submits an `AllResources` invoke transaction with `l2_gas.max_price_per_unit = 55 fri`.
5. `validate_tx_l2_gas_price_within_threshold` computes `threshold = 50`, sees `55 >= 50`, and returns `Ok(())`. Transaction is admitted to the mempool.
6. The batcher builds block N+1 with `l2_gas_price = 112 fri`. Blockifier's `check_fee_bounds` computes the required price as `112 fri`, sees `55 < 112`, and returns `TransactionFeeError::InsufficientResourceBounds { MaxGasPriceTooLow }`. The transaction is reverted.
7. The attacker repeats at scale, filling the mempool with transactions that always pass the stale gateway check but always fail execution.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-241)
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
        }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-383)
```rust
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
```

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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
