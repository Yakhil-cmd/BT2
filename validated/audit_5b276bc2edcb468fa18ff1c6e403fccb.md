### Title
Gateway Stateful Admission Validates L2 Gas Price Against Previous Block Price Instead of Next Block Price — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` compares the transaction's `max_price_per_unit` against the **previous (committed) block's** L2 gas price, but the transaction will be executed at the **next block's** L2 gas price, which is computed by the EIP-1559 `calculate_next_base_gas_price` mechanism. The two values diverge by up to `1/gas_price_max_change_denominator` (≈ 2%) per block. The code itself carries an explicit TODO acknowledging the wrong reference point is used.

### Finding Description

In `validate_resource_bounds`, the gateway reads the current committed block's L2 gas price:

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
let threshold = (Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128)
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
``` [2](#0-1) 

The default `min_gas_price_percentage` is 100, so the gateway requires `tx_l2_gas_price >= previous_block_price` exactly. [3](#0-2) 

The next block's L2 gas price is computed by `calculate_next_base_gas_price` using the EIP-1559 formula. With `gas_price_max_change_denominator = 48`, a fully-congested block raises the price by `gas_delta / (gas_target * 48)`. At maximum congestion (`gas_used = max_block_size`, `gas_target = max_block_size/2`), the price rises by ≈ 2.08% per block. [4](#0-3) 

The blockifier's `check_fee_bounds` enforces the **actual next-block** gas price during execution:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

### Impact Explanation

**Scenario A — price rising (congested network):**
A user submits a transaction with `max_price_per_unit = P_prev` (the previous block's price). The gateway admits it because `P_prev >= P_prev * 100%`. The next block's price is `P_next ≈ P_prev * 1.021`. The blockifier rejects the transaction with `MaxGasPriceTooLow`. The transaction is included in the block as a revert; the user pays fees for a failed transaction. The gateway admitted an invalid transaction.

**Scenario B — price falling (under-utilized network):**
A user submits a transaction with `max_price_per_unit = P_next` (the actual next-block price, which is lower than `P_prev`). The gateway rejects it because `P_next < P_prev * 100%`. The transaction would have succeeded during execution. The gateway rejected a valid transaction.

Both scenarios match the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block based on actual gas usage. Any block that is not exactly at the gas target (which is the common case) produces a price divergence between `P_prev` and `P_next`. The divergence is up to ≈ 2% per block. Users who set `max_price_per_unit` to the current block's price (a natural and documented pattern) are systematically affected during periods of changing network load.

### Recommendation

Replace the reference price in `validate_resource_bounds` with the **next block's** L2 gas price, as the TODO comment already acknowledges:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [6](#0-5) 

The next-block price is available from the block header's `next_l2_gas_price` field (used in sync flows, e.g. `sync_block.block_header_without_hash.next_l2_gas_price`). The gateway should read this field instead of the current block's `strk_gas_prices.l2_gas_price`.

### Proof of Concept

1. Observe the current committed block's L2 gas price: `P_prev = 30_000_000_000` fri (30 Gwei).
2. The current block is fully congested: `gas_used = max_block_size = 5_000_000_000`, `gas_target = 2_500_000_000`, `denominator = 48`.
3. `price_change = P_prev * (gas_used - gas_target) / (gas_target * 48) = 30e9 * 2.5e9 / (2.5e9 * 48) ≈ 625_000_000`.
4. `P_next = 30_000_000_000 + 625_000_000 = 30_625_000_000` fri.
5. Submit an `InvokeV3` transaction with `l2_gas.max_price_per_unit = 30_000_000_000`.
6. Gateway check: `30_000_000_000 >= 30_000_000_000 * 100% = 30_000_000_000` → **admitted**.
7. Blockifier check at execution: `30_000_000_000 < 30_625_000_000` → **`MaxGasPriceTooLow`**, transaction reverted, fees charged.

The gateway admitted a transaction that the blockifier will reject, confirming the invariant is broken.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-240)
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
