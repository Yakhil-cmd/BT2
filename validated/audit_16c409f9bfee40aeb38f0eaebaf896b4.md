### Title
Gateway L2 Gas Price Threshold Rounded Down via `.to_integer()`, Admitting Transactions Below the Intended Minimum — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` computes the admission threshold by multiplying `min_gas_price_percentage / 100` (a `Ratio<u128>`) by the previous block's L2 gas price and then calling `.to_integer()`, which performs **floor (truncating) division**. When `min_gas_price_percentage × previous_block_l2_gas_price` is not evenly divisible by 100, the computed threshold is 1 FRI unit lower than the true fractional threshold. A transaction whose `max_price_per_unit` equals the floored value passes the check even though it is strictly below the intended percentage of the previous block price.

### Finding Description

In `validate_tx_l2_gas_price_within_threshold`:

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

`Ratio::to_integer()` from `num_rational` returns `⌊numerator / denominator⌋`. When `min_gas_price_percentage × price` has a non-zero remainder modulo 100, the threshold is silently rounded down by up to 1 FRI unit. The check `tx_l2_gas_price.0 < threshold` then passes for a price equal to the floored value, even though the true threshold is `threshold + fraction`.

**Concrete example:**
- `previous_block_l2_gas_price = 101` FRI, `min_gas_price_percentage = 50`
- True threshold = `50/100 × 101 = 50.5` FRI
- Computed threshold = `⌊50.5⌋ = 50` FRI
- A transaction with `tx_l2_gas_price = 50` satisfies `50 < 50 → false`, so it is **admitted**
- The intended invariant (`tx_price ≥ 50.5`) is violated

The existing unit tests in `stateful_transaction_validator_test.rs` only exercise round numbers (`previous_block_l2_gas_price = 100`, `min_gas_price_percentage ∈ {0, 10, 50, 100}`), where `percentage × price` is always divisible by 100, so the rounding defect is never exercised.

### Impact Explanation

The gateway's stateful admission check is the last price-floor guard before a transaction enters the mempool. Bypassing it by 1 FRI unit allows a transaction with a gas price strictly below the operator-configured minimum percentage of the previous block price to be accepted and sequenced. This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

Any block whose L2 gas price is not a multiple of `100 / gcd(min_gas_price_percentage, 100)` triggers the rounding. With the default `min_gas_price_percentage = 100` there is no rounding (100/100 = 1 exactly). However, operators who set a non-100 percentage (e.g., 80, 50, 90) will encounter this on most blocks, since real gas prices are not multiples of 100. An attacker who observes the previous block's L2 gas price can deterministically compute the floored threshold and submit a transaction at exactly that price.

### Recommendation

Replace `.to_integer()` (floor) with ceiling division so the threshold is never lower than the true fractional value:

```rust
// Use ceil() instead of to_integer() to avoid rounding the threshold down.
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()
    .to_integer();
```

This mirrors the pattern already used elsewhere in the codebase (e.g., `convert_l1_to_l2_gas_price_round_up`, `sierra_gas_to_l1_gas_amount_round_up`) where rounding up is explicitly chosen to prevent under-charging or under-enforcing.

### Proof of Concept

```
previous_block_l2_gas_price = 101  (NonzeroGasPrice)
min_gas_price_percentage     = 50  (u8, configured)

Ratio::new(50u128, 100u128) * 101u128
  = Ratio::new(5050, 100)
  = Ratio::new(101, 2)          // reduced

.to_integer() = 50              // floor(50.5) = 50

Transaction sets tx.resource_bounds.l2_gas.max_price_per_unit = 50

Check: 50 < 50  →  false  →  transaction ADMITTED

True threshold = 50.5, so price 50 should be REJECTED.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-371)
```rust
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
```

**File:** crates/apollo_gateway_config/src/config.rs (L285-296)
```rust
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L229-286)
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
```

**File:** crates/blockifier/src/blockifier_versioned_constants.rs (L369-387)
```rust
    /// Converts from L1 gas price to L2 gas price with **upward rounding**, based on the
    /// conversion of a Cairo step from Sierra gas to L1 gas.
    pub fn convert_l1_to_l2_gas_price_round_up(&self, l1_gas_price: GasPrice) -> GasPrice {
        (*(resource_cost_to_u128_ratio(self.sierra_gas_in_l1_gas_amount()) * l1_gas_price.0)
            .ceil()
            .numer())
        .into()
    }

    /// Converts L1 gas amount to Sierra (L2) gas amount with **upward rounding**.
    pub fn l1_gas_to_sierra_gas_amount_round_up(&self, l1_gas_amount: GasAmount) -> GasAmount {
        // The amount ratio is the inverse of the price ratio.
        (*(self.sierra_gas_in_l1_gas_amount().inv() * l1_gas_amount.0).ceil().numer()).into()
    }

    /// Converts Sierra (L2) gas amount to L1 gas amount with **upward rounding**.
    pub fn sierra_gas_to_l1_gas_amount_round_up(&self, l2_gas_amount: GasAmount) -> GasAmount {
        (*(self.sierra_gas_in_l1_gas_amount() * l2_gas_amount.0).ceil().numer()).into()
    }
```
