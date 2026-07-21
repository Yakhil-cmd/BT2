### Title
Gateway Admission Threshold Rounds Down, Allowing Transactions Below Intended Minimum Gas Price - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price using `Ratio::to_integer()`, which performs **floor (truncation) division**. When the true threshold is non-integer, the computed threshold is one unit lower than it should be, and a transaction whose `max_price_per_unit` equals the floored value is admitted even though it is strictly below the intended minimum.

### Finding Description

In `StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold`:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← floor division
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
```

`Ratio::to_integer()` in `num_rational` truncates toward zero (floor for positive values). The threshold is therefore `⌊ (min_gas_price_percentage / 100) × previous_price ⌋`.

Whenever `min_gas_price_percentage × previous_price` is not divisible by 100, the true threshold is fractional and the floored integer is strictly less than it. The admission check `tx_l2_gas_price.0 < threshold` then passes for a price equal to the floored value, even though that price is below the true threshold.

**Concrete example:**
- `previous_block_l2_gas_price = 101 fri`
- `min_gas_price_percentage = 50`
- True threshold = `50/100 × 101 = 50.5 fri`
- Computed threshold = `⌊50.5⌋ = 50 fri`
- A transaction with `max_price_per_unit = 50` satisfies `50 < 50` → **false**, so it is **admitted**, despite being below the intended 50.5 fri floor.

The correct computation should use ceiling division: `⌈ (min_gas_price_percentage / 100) × previous_price ⌉`, i.e., replace `.to_integer()` with `.ceil().to_integer()` (or equivalently `(numerator + denominator - 1) / denominator`). [1](#0-0) 

The existing test suite only exercises cases where `min_gas_price_percentage × previous_price` is exactly divisible by 100 (e.g., 100 × 100, 50 × 100), so the floor/ceiling distinction never surfaces in tests. [2](#0-1) 

### Impact Explanation

The gateway's stateful path is the last admission gate before a transaction enters the mempool. A transaction admitted here with a gas price below the intended minimum will be sequenced and executed. The sequencer accepts a transaction it should have rejected, violating the admission invariant. This maps directly to: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The condition is triggered whenever `min_gas_price_percentage × previous_block_l2_gas_price` is not divisible by 100. Because `previous_block_l2_gas_price` is an EIP-1559-style dynamic value updated every block, the vast majority of blocks will produce a non-integer threshold. Any user who inspects the previous block's gas price and submits a transaction with `max_price_per_unit = ⌊threshold⌋` will reliably trigger this. No special privileges are required.

### Recommendation

Replace `.to_integer()` with ceiling division:

```rust
// Before (floor):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();

// After (ceiling):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()
    .to_integer();
```

`Ratio::ceil()` is provided by `num_rational` and returns the smallest integer ≥ the ratio, which is the correct direction when computing a minimum that a user must meet.

### Proof of Concept

1. Observe `previous_block_l2_gas_price = 101 fri` and `min_gas_price_percentage = 50` (the default is 100, but operators may lower it; any odd `previous_price` with `percentage = 50` suffices).
2. Compute `threshold = ⌊50/100 × 101⌋ = ⌊50.5⌋ = 50`.
3. Submit an `AllResources` V3 invoke transaction with `l2_gas.max_price_per_unit = 50`.
4. The check `50 < 50` is false → transaction is admitted to the mempool.
5. The true intended threshold is 50.5 fri; the transaction's price of 50 fri is below it. [3](#0-2) [4](#0-3)

### Citations

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L229-287)
```rust
#[rstest]
#[case::tx_gas_price_meets_threshold_exactly_pass(
    100_u128.try_into().unwrap(),
    100,
    100_u128.into(),
    Ok(())
)]
#[case::tx_gas_price_below_threshold_fail(
    100_u128.try_into().unwrap(),
    100,
    99_u128.into(),
    Err(StarknetError {
        code: StarknetErrorCode::UnknownErrorCode(
            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
        ),
        message: "Transaction L2 gas price 99 is below the required threshold 100.".to_string(),
    })
)]
#[case::tx_gas_price_meets_threshold_with_factor_pass(
    100_u128.try_into().unwrap(),
    50,
    50_u128.into(),
    Ok(())
)]
#[case::tx_gas_price_above_threshold_with_factor_pass(
    100_u128.try_into().unwrap(),
    50,
    51_u128.into(),
    Ok(())
)]
#[case::tx_gas_price_below_threshold_with_factor_fail(
    100_u128.try_into().unwrap(),
    50,
    49_u128.into(),
    Err(StarknetError {
        code: StarknetErrorCode::UnknownErrorCode(
            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
        ),
        message: "Transaction L2 gas price 49 is below the required threshold 50.".to_string(),
    })
)]
#[case::gas_price_check_disabled_when_percentage_zero_pass(
    100_u128.try_into().unwrap(),
    0,
    0_u128.into(),
    Ok(()),
)]
#[case::tx_gas_price_zero_fails_when_percentage_nonzero_fail(
    100_u128.try_into().unwrap(),
    10,
    0_u128.into(),
    Err(StarknetError {
        code: StarknetErrorCode::UnknownErrorCode(
            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
        ),
        message: "Transaction L2 gas price 0 is below the required threshold 10.".to_string(),
    })
)]
#[tokio::test]
```

**File:** crates/apollo_gateway_config/src/config.rs (L285-287)
```rust
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}
```
