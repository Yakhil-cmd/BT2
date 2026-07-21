### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Admitting Transactions That Will Fail Execution - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` computes its admission threshold from the **previous block's** `l2_gas_price` field rather than from `next_l2_gas_price` (the EIP-1559-derived price for the block being built). When the L2 gas price is rising, the threshold is too low: transactions whose `max_price_per_unit` clears the stale threshold but falls below the actual next-block price are admitted to the mempool and then fail at blockifier pre-validation. The code itself acknowledges the defect with a `TODO` comment at the exact line.

---

### Finding Description

`validate_resource_bounds` reads the gas price reference point via `get_block_info()`:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
``` [1](#0-0) 

`get_block_info()` constructs a `BlockInfo` from the committed block header, mapping `header.l2_gas_price.price_in_fri` into `strk_gas_prices.l2_gas_price`: [2](#0-1) 

The `StorageBlockHeader` stores two distinct fields: `l2_gas_price` (the price used in that block) and `next_l2_gas_price` (the EIP-1559 price computed for the **next** block): [3](#0-2) 

`next_l2_gas_price` is computed by `calculate_next_base_gas_price` / `calculate_next_l2_gas_price_for_fin` and written into the fin payload and block header at decision time: [4](#0-3) 

The threshold check then becomes:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
``` [5](#0-4) 

Because `previous_block_l2_gas_price` is `l2_gas_price` (not `next_l2_gas_price`), the threshold is wrong whenever the two values diverge — which is the normal EIP-1559 behavior every block.

The blockifier's own `check_fee_bounds` enforces the correct price at execution time:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [6](#0-5) 

So the gateway and the blockifier use different reference prices for the same invariant.

---

### Impact Explanation

**Rising-price scenario** (previous block was congested, `next_l2_gas_price > l2_gas_price`):

- Correct gateway threshold = `pct% × next_l2_gas_price`
- Actual gateway threshold = `pct% × l2_gas_price` ← too low
- Transactions with `max_price_per_unit ∈ [pct% × l2_gas_price, next_l2_gas_price)` pass gateway admission and enter the mempool, but are rejected by `check_fee_bounds` at blockifier pre-validation.
- These transactions pollute the mempool, consume batcher resources, and produce failed executions — matching the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

**Falling-price scenario** (previous block was under-utilized, `next_l2_gas_price < l2_gas_price`):

- Actual gateway threshold is higher than necessary; transactions with `max_price_per_unit ∈ [pct% × next_l2_gas_price, pct% × l2_gas_price)` are rejected at the gateway. However, those transactions would also fail the blockifier's `max_price_per_unit >= actual_gas_price` check, so no economically valid transaction is lost.

The primary exploitable direction is the rising-price case.

---

### Likelihood Explanation

EIP-1559 adjusts `next_l2_gas_price` every block based on gas usage. Any block that is more than 50% full causes `next_l2_gas_price > l2_gas_price`. Under normal network load this divergence is routine, making the condition continuously reachable by any unprivileged user submitting a transaction with a gas price in the gap.

---

### Recommendation

Replace the `l2_gas_price` field lookup with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait (or its `get_block_info` implementation) should expose `next_l2_gas_price` so that `validate_resource_bounds` can use it:

```rust
// Before (stale):
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info().await?
    .gas_prices.strk_gas_prices.l2_gas_price;

// After (correct):
let next_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price().await?;  // reads header.next_l2_gas_price
```

This resolves the `TODO(Arni)` comment at line 229 and aligns the gateway admission threshold with the price the blockifier will actually enforce.

---

### Proof of Concept

1. Previous committed block: `l2_gas_price = 100 FRI`, block was 90% full.
2. EIP-1559 computes `next_l2_gas_price = 112 FRI` (≈ +12.5% for 90% utilization at default denominator).
3. Gateway config: `min_gas_price_percentage = 50`.
4. Stale gateway threshold = `50% × 100 = 50 FRI`.
5. Correct gateway threshold = `50% × 112 = 56 FRI`.
6. Attacker/user submits an invoke transaction with `l2_gas.max_price_per_unit = 53 FRI`.
7. **Gateway**: `53 ≥ 50` → **admitted** to mempool.
8. **Blockifier** `check_fee_bounds`: `53 < 112` → `MaxGasPriceTooLow` → transaction fails pre-validation.
9. The transaction occupied a mempool slot and consumed batcher execution resources for a transaction that was never going to succeed.

The gap between the stale threshold (50 FRI) and the correct threshold (56 FRI) is directly proportional to the block's congestion level and grows with each consecutive congested block, since `next_l2_gas_price` compounds while the gateway's reference price lags one block behind.

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

**File:** crates/apollo_storage/src/header.rs (L85-90)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-139)
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
