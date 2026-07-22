### Title
Gateway Stateful Admission Uses Stale Previous-Block L2 Gas Price Instead of Next-Block Price — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validator checks a transaction's `max_price_per_unit` against the **previous block's** L2 gas price, while actual block execution uses the **next block's** L2 gas price set by the proposer. Transactions whose `max_price_per_unit` falls between the two prices pass gateway admission and enter the mempool, but are then rejected by the blockifier during block building with `MaxGasPriceTooLow`. The code itself acknowledges this with a TODO comment at the exact line of the stale read.

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the threshold for admission is derived from the **previous** committed block's gas price:

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

The threshold computed from this stale price is:

```
threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price
```

With the production default of `min_gas_price_percentage = 100`, the threshold equals exactly the previous block's price. [2](#0-1) 

The same stale price is also used inside `run_validate_entry_point`, which builds the blockifier `BlockContext` from the previous block's `BlockInfo` (only incrementing the block number, not updating gas prices):

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

So both the gateway's own price check and the blockifier's `check_fee_bounds` inside `perform_pre_validation_stage` use the previous block's L2 gas price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

However, the actual block proposer computes the **next** block's L2 gas price via the EIP-1559 formula in `calculate_next_base_gas_price`, which can be higher than the previous block's price when gas usage exceeds the target:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [5](#0-4) 

The proposer embeds this higher price in the `ProposalInit` block info, and the blockifier uses it during actual execution. A transaction admitted by the gateway with `max_price_per_unit == P_prev` will fail at execution time if the proposer sets `P_next > P_prev`.

### Impact Explanation

**High — Mempool/gateway admission accepts transactions that are invalid for the next block.**

Any transaction with `max_price_per_unit` in the range `[P_prev, P_next)` passes all gateway checks (both the explicit `validate_resource_bounds` check and the blockifier pre-validation inside `run_validate_entry_point`) but is rejected by the blockifier during actual block building with `MaxGasPriceTooLow`. These transactions occupy mempool slots, consume gateway validation resources, and are never sequenced. In a rising-price environment (high network load), this window is continuously open and can be exploited to flood the mempool with permanently-unsequenceable transactions.

The reverse direction also holds: when `P_next < P_prev` (falling prices), the gateway rejects transactions with `max_price_per_unit` in `[P_next, P_prev)` that would be perfectly valid for the next block, causing valid transactions to be incorrectly rejected before sequencing.

### Likelihood Explanation

The L2 gas price is adjusted every block by the EIP-1559 formula. Under sustained high load (gas usage above target), the price rises monotonically each block. This is a normal operating condition, not an edge case. With the default `min_gas_price_percentage = 100`, there is zero buffer: any transaction priced exactly at the previous block's price is at risk. An unprivileged user can trigger this by simply submitting a transaction with `max_price_per_unit` set to the last observed block price, which is the natural behavior of any wallet that reads the latest block to set its gas price.

### Recommendation

Replace the stale `get_block_info()` read with the computed next-block L2 gas price, as the TODO comment already acknowledges:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The next-block L2 gas price should be derived from `calculate_next_base_gas_price` (or `calculate_next_l2_gas_price_for_fin`) using the latest block's gas usage and the current block's price, matching the value the proposer will embed in `ProposalInit`. The same corrected price should be passed to `run_validate_entry_point` so that the blockifier pre-validation inside the gateway uses the same price as actual execution.

### Proof of Concept

1. Observe the current committed block's L2 gas price: `P_prev`.
2. Observe that the network is under high load (gas usage > target), so the next block's price will be `P_next = P_prev + delta` where `delta > 0`.
3. Submit an `InvokeV3` transaction with `AllResources` bounds and `l2_gas.max_price_per_unit = P_prev`.
4. Gateway `validate_resource_bounds` computes `threshold = 100% * P_prev = P_prev`. Since `P_prev >= P_prev`, the check passes.
5. Gateway `run_validate_entry_point` builds a `BlockContext` with `block_info.gas_prices.l2_gas_price = P_prev` (stale). The blockifier's `check_fee_bounds` checks `P_prev >= P_prev` — passes.
6. Transaction is admitted to the mempool.
7. The proposer builds the next block with `l2_gas_price = P_next > P_prev`.
8. The blockifier's `check_fee_bounds` during actual execution checks `P_prev >= P_next` — **fails** with `MaxGasPriceTooLow`.
9. The transaction is never included in any block and permanently occupies a mempool slot.

Repeat steps 3–9 at high frequency to exhaust mempool capacity with unsequenceable transactions, degrading admission for legitimate users. [6](#0-5) [7](#0-6) [8](#0-7)

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
