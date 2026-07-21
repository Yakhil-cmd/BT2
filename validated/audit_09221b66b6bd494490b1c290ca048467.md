### Title
Gateway Stateful Validator Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` for Admission Threshold, Allowing Transactions with Insufficient Gas Price to Enter the Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `gas_prices.strk_gas_prices.l2_gas_price` from the latest committed block to compute the admission threshold. However, the transaction will be executed in the **next** block, which uses `next_l2_gas_price` (a distinct field stored in the same block header). When the network is congested, `next_l2_gas_price > l2_gas_price`, so the threshold is computed from the wrong (lower) value. Transactions whose L2 gas price falls in the gap `[threshold_based_on_current, next_l2_gas_price)` pass gateway admission but are rejected by the blockifier's `check_fee_bounds` during block building.

The code itself acknowledges the problem with a TODO comment directly at the defect site.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price reference value as:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;          // ← current block's price, NOT next block's price
``` [1](#0-0) 

This value is then used to compute the admission threshold:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...GAS_PRICE_TOO_LOW...);
}
``` [2](#0-1) 

The block header stores **two distinct** L2 gas price fields:
- `l2_gas_price` — the price used for the already-committed block.
- `next_l2_gas_price` — the EIP-1559-adjusted price for the **next** block, computed by `calculate_next_l2_gas_price_for_fin` and stored in the header. [3](#0-2) 

The blockifier's `check_fee_bounds` (called in `perform_pre_validation_stage`) enforces that `tx_l2_gas_price >= block_l2_gas_price` where `block_l2_gas_price` is the **next** block's price. When the current block is congested (gas used > gas target), `calculate_next_base_gas_price` increases the price:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [4](#0-3) 

The gateway threshold is therefore anchored to the **old** (lower) price, while the blockifier enforces the **new** (higher) price. Any transaction with:

```
(min_gas_price_percentage / 100) * current_l2_gas_price
    ≤ tx_l2_gas_price
    < next_l2_gas_price
```

passes gateway admission, enters the mempool, and is then rejected by the blockifier with `MaxGasPriceTooLow` / `InsufficientResourceBounds` during block building.

---

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

Concretely:
- Transactions that will unconditionally fail blockifier pre-validation are admitted to the mempool.
- The batcher wastes execution budget attempting to include them; they are silently dropped from the block.
- An attacker can deliberately craft transactions priced just below `next_l2_gas_price` to flood the mempool and consume batcher resources at zero cost (the transactions never pay fees because they never execute).
- The window grows proportionally with congestion: the higher the block utilization, the larger the gap between `l2_gas_price` and `next_l2_gas_price`, and the wider the exploitable price band.

---

### Likelihood Explanation

- Triggered automatically whenever a block is more than 50 % full (the EIP-1559 target), which is a normal operating condition under load.
- No special privileges required; any user submitting a V3 (`AllResources`) transaction can exploit this.
- The `min_gas_price_percentage` config amplifies the window: at 50 %, the threshold is half the current price, so the exploitable band spans from `0.5 × current_price` to `next_price`.

---

### Recommendation

Replace the read of `l2_gas_price` with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait (or its implementation) should expose the `next_l2_gas_price` field that is already present in `BlockHeaderWithoutHash`:

```rust
// Before (wrong):
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;

// After (correct):
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method reading next_l2_gas_price from the header
    .await?;
```

This mirrors the fix described in the external report: use the value that corresponds to the actual execution context (the next block), not the already-committed context (the current block).

---

### Proof of Concept

1. Observe the current committed block's `l2_gas_price` = P and `next_l2_gas_price` = P′ where P′ > P (congested block, e.g. 75 % full → P′ ≈ 1.0125 × P per the EIP-1559 formula).
2. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P` (equals current price, above the gateway threshold when `min_gas_price_percentage ≤ 100`).
3. Gateway calls `validate_tx_l2_gas_price_within_threshold(P, threshold = P)` → passes.
4. Transaction enters the mempool.
5. Batcher picks the transaction for the next block (price = P′).
6. Blockifier calls `check_fee_bounds`: `P < P′` → `MaxGasPriceTooLow` → transaction rejected, never included, no fee charged. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_protobuf/src/converters/header.rs (L175-178)
```rust
        let next_l2_gas_price = u128::from(
            value.next_l2_gas_price.ok_or(missing("SignedBlockHeader::next_l2_gas_price"))?,
        )
        .into();
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
