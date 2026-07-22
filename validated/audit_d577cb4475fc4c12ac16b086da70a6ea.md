### Title
Gateway L2 Gas Price Threshold Computed with Floor Instead of Ceiling Allows Under-Priced Transactions Through Admission - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price using `Ratio::to_integer()`, which truncates (floors) the result. The invariant for a minimum-price guard is that the threshold must round **up** (ceiling) so that the sequencer is never under-protected. The floor rounding allows transactions whose `max_price_per_unit` is exactly 1 FRI below the intended threshold to pass gateway admission.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the stateful validator computes the minimum acceptable L2 gas price as a percentage of the previous block's L2 gas price:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← floor division
if tx_l2_gas_price.0 < threshold {
    return Err(...)
}
```

`Ratio::to_integer()` in Rust's `num_rational` crate returns the integer part of the ratio, which is the **floor** for positive values. For example:

- `min_gas_price_percentage = 50`, `previous_block_l2_gas_price = 101 FRI`
- `Ratio::new(50, 100) * 101 = Ratio::new(5050, 100) = Ratio::new(101, 2)`
- `.to_integer()` → **50** (floor of 50.5)
- Intended threshold (ceiling): **51**

A transaction with `tx_l2_gas_price = 50` satisfies `50 < 50 == false`, so it passes the check. The intended policy requires `tx_l2_gas_price >= 51`.

The analog to the ERC4626 bug is exact: just as `previewWithdraw` must round **up** to protect the vault (the party computing "how much the user must provide"), the gateway threshold must round **up** to protect the sequencer (the party computing "how low a gas price is acceptable"). Using floor instead of ceiling allows a transaction that is 1 FRI below the intended minimum to slip through admission.

### Impact Explanation

The gateway stateful path is the sequencer's first line of defense against under-priced transactions. A transaction admitted with a gas price 1 FRI below the intended threshold will:

1. Pass `validate_tx_l2_gas_price_within_threshold` (due to floor rounding).
2. Enter the mempool.
3. If the current block's L2 gas price equals the previous block's (stable market), also pass `check_fee_bounds` in the blockifier (since `max_price_per_unit >= actual_gas_price`).
4. Execute successfully and be included in a block.

The sequencer's admission invariant — "reject transactions whose L2 gas price is below `ceil(percentage × previous_price / 100)`" — is violated. The discrepancy is bounded at 1 FRI per transaction, but the direction of the error consistently favors the submitter over the sequencer, matching the ERC4626 pattern exactly.

**Matching impact:** *High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

### Likelihood Explanation

Any unprivileged user can submit a V3 transaction (`AllResources` bounds) with `max_price_per_unit` set to exactly `floor(percentage × previous_price / 100)`. No special knowledge or privilege is required. The condition is triggered whenever `min_gas_price_percentage` does not evenly divide `previous_block_l2_gas_price`, which is the common case for any non-round gas price value. With the default `min_gas_price_percentage = 100`, the ratio is always an integer and no rounding occurs; the bug is exposed for any other configured percentage (e.g., 50, 80, 90).

### Recommendation

Replace `.to_integer()` with `.ceil().to_integer()` so the threshold rounds up:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()          // ← add ceiling
    .to_integer();
```

This ensures the computed threshold is always at least as large as the true fractional threshold, protecting the sequencer from under-priced transactions.

### Proof of Concept

```
previous_block_l2_gas_price = 101 FRI
min_gas_price_percentage     = 50

Current code:
  threshold = floor(50/100 × 101) = floor(50.5) = 50
  tx with max_price_per_unit = 50 → 50 < 50 is false → ADMITTED ✓ (wrong)

Fixed code:
  threshold = ceil(50/100 × 101) = ceil(50.5) = 51
  tx with max_price_per_unit = 50 → 50 < 51 is true → REJECTED ✓ (correct)
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
}
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L229-270)
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
```
