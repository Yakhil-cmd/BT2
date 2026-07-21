### Title
Gateway L2 Gas Price Admission Threshold Uses Stale Previous-Block Price, Causing Valid Transactions to Be Rejected or Invalid Transactions to Be Admitted - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The stateful gateway validator's `validate_resource_bounds` function computes the minimum acceptable L2 gas price threshold using the **previous** block's L2 gas price rather than the **next** block's price. The code itself carries an explicit TODO acknowledging this. Because the EIP-1559 mechanism adjusts the next block's price every block, the threshold is systematically wrong: when the price falls the gateway rejects transactions that would be valid for the next block; when the price rises the gateway admits transactions that will fail during blockifier execution.

### Finding Description

In `validate_resource_bounds`, the gateway reads the previous block's L2 gas price and passes it directly to the threshold check:

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
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(StarknetError { ... });
}
``` [2](#0-1) 

The default `min_gas_price_percentage` is **100**, so the threshold equals the previous block's price exactly: [3](#0-2) 

The EIP-1559 mechanism (`calculate_next_base_gas_price`) adjusts the next block's price based on the previous block's gas usage relative to the target: [4](#0-3) 

This creates two divergent failure modes:

**Case A — price decreasing (previous block under-utilised):**
`next_block_price < previous_block_price`. The gateway threshold is anchored to `previous_block_price` (too high). Any transaction whose `max_price_per_unit` satisfies `next_block_price ≤ max_price_per_unit < previous_block_price` is rejected with `GAS_PRICE_TOO_LOW`, even though it would pass `check_fee_bounds` in the blockifier (which uses the actual next-block price).

**Case B — price increasing (previous block over-utilised):**
`next_block_price > previous_block_price`. The gateway threshold is `previous_block_price` (too low). Transactions with `previous_block_price ≤ max_price_per_unit < next_block_price` pass the gateway and enter the mempool, but will fail `check_fee_bounds` during blockifier pre-validation with `MaxGasPriceTooLow`: [5](#0-4) 

The blockifier's `check_fee_bounds` uses the **actual** block gas price from `block_info.gas_prices`, not the previous block's price, so the two checks are structurally inconsistent.

### Impact Explanation

**Case A** — valid transactions are rejected at the gateway before sequencing. Users whose `max_price_per_unit` is set to the correct next-block price (e.g., computed from the EIP-1559 formula) are turned away even though their transaction would execute successfully. This is a direct "rejects valid transactions before sequencing" impact.

**Case B** — invalid transactions are admitted to the mempool. They consume mempool capacity and batcher resources, then revert during pre-validation. An attacker who observes that the previous block was under-utilised can flood the mempool with transactions priced just above `previous_block_price` knowing they will all fail execution, constituting a low-cost DoS against the mempool and batcher.

Both outcomes match the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 mechanism adjusts the price every block. With a `gas_price_max_change_denominator` of 8 (the default derived from versioned constants), the price can shift by up to ~12.5 % per block. In a live network the price changes on virtually every block, so the mismatch is present continuously. Any user who computes `max_price_per_unit` from the published next-block price formula will be affected by Case A whenever the network is lightly loaded.

### Recommendation

Replace `previous_block_l2_gas_price` with the computed next-block L2 gas price. The `calculate_next_l2_gas_price_for_fin` function already exists and accepts the previous block's price and gas usage: [6](#0-5) 

The gateway should call this function (or read the pre-computed value from the block header once it is available, as the TODO notes) and pass the result to `validate_tx_l2_gas_price_within_threshold` instead of the raw previous-block price.

### Proof of Concept

1. Observe that the previous block consumed less gas than the EIP-1559 target.
2. Compute `next_price = calculate_next_base_gas_price(previous_price, gas_used, gas_target, min_price)` — this yields `next_price < previous_price`.
3. Submit an `AllResources` invoke transaction with `l2_gas.max_price_per_unit = next_price`.
4. The gateway computes `threshold = previous_price * 100 / 100 = previous_price`.
5. Because `next_price < previous_price`, the check `tx_l2_gas_price.0 < threshold` is true.
6. The gateway returns `"Transaction L2 gas price {next_price} is below the required threshold {previous_price}."` and rejects the transaction.
7. Yet the blockifier's `check_fee_bounds` would accept the same transaction because it compares `max_price_per_unit` against the actual next-block price, which equals `next_price`.

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

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L54-77)
```rust
/// Compute the next L2 gas price (for the fin or for updating state). Respects override when set.
pub fn calculate_next_l2_gas_price_for_fin(
    current_l2_gas_price: GasPrice,
    height: BlockNumber,
    l2_gas_used: GasAmount,
    override_l2_gas_price_fri: Option<u128>,
    min_l2_gas_price_per_height: &[PricePerHeight],
    fee_actual: Option<GasPrice>,
) -> GasPrice {
    if let Some(override_value) = override_l2_gas_price_fri {
        info!(
            "L2 gas price ({}) is not updated, remains on override value of {override_value} fri",
            current_l2_gas_price.0
        );
        return GasPrice(override_value);
    }
    let gas_target = VersionedConstants::latest_constants().gas_target;
    let config_min = get_min_gas_price_for_height(height, min_l2_gas_price_per_height);
    let effective_min = match fee_actual {
        Some(fa) => GasPrice(max(config_min.0, fa.0)),
        None => config_min,
    };
    calculate_next_base_gas_price(current_l2_gas_price, l2_gas_used, gas_target, effective_min)
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
