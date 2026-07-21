### Title
Gateway L2 Gas Price Threshold Rounded Down Admits Transactions Below the Configured Minimum — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price by multiplying `min_gas_price_percentage / 100` by the previous block's L2 gas price and calling `.to_integer()`, which **truncates toward zero (floor)**. Because the threshold is rounded down instead of up, any transaction whose `max_price_per_unit` falls in the half-open interval `[floor(pct × prev / 100), ceil(pct × prev / 100))` passes the check even though it is strictly below the operator-configured minimum fraction of the previous block price. This is the direct Sequencer analog of the UniV3Oracle tick-rounding bug: the rounding direction is wrong for the party whose invariant must be protected.

### Finding Description

In `validate_tx_l2_gas_price_within_threshold`:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← truncates (floor), not ceiling
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
```

`num_rational::Ratio::to_integer()` is documented to truncate toward zero, i.e. it is a floor for positive values. The intended invariant is:

```
tx_l2_gas_price  ≥  ceil(min_gas_price_percentage × prev_price / 100)
```

but the code enforces only:

```
tx_l2_gas_price  ≥  floor(min_gas_price_percentage × prev_price / 100)
```

Whenever `min_gas_price_percentage × prev_price` is not divisible by 100, the floored threshold is strictly less than the true threshold, opening a 1-unit gap. A transaction with `tx_l2_gas_price = floor(...)` satisfies `tx_l2_gas_price >= threshold` and is admitted, even though it is below the operator's intended minimum.

**Concrete example:**
- `previous_block_l2_gas_price = 101 FRI`
- `min_gas_price_percentage = 90`
- True threshold = `90 × 101 / 100 = 90.9 FRI` → should require ≥ 91
- Floored threshold = `90`
- A transaction with `max_price_per_unit = 90` is admitted (90 ≥ 90) despite being below the intended 90.9 FRI minimum.

The gap is at most 1 FRI per gas unit, but with the maximum allowed L2 gas amount of 1,210,000,000 units (from `StatelessTransactionValidatorConfig::default()`), the maximum underpayment per transaction is ~1.21 STRK. More importantly, the admission invariant itself is broken: the gateway certifies to the mempool that the transaction meets the configured price floor when it does not.

The existing test suite only exercises cases where `pct × prev` is exactly divisible by 100 (e.g., `prev=100, pct=50 → 50.0`; `prev=100, pct=100 → 100.0`), so the rounding error is never exercised and the bug is not caught.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's stateful path is the gatekeeper that enforces the operator-configured `min_gas_price_percentage` policy. Transactions that slip through with a gas price below the true threshold are forwarded to the mempool and eventually sequenced. The sequencer's fee revenue is reduced by up to 1 FRI × gas_used per such transaction, and the admission invariant that downstream components rely on is silently violated.

### Likelihood Explanation

The bug triggers whenever `min_gas_price_percentage × previous_block_l2_gas_price` is not divisible by 100. Since L2 gas prices are arbitrary integers driven by EIP-1559 dynamics, this condition holds for the vast majority of blocks. Any unprivileged user who observes the previous block's L2 gas price can trivially compute the floored threshold and submit a transaction at exactly that value to exploit the gap.

### Recommendation

Replace `.to_integer()` with `.ceil().to_integer()` so the threshold is rounded up:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()
    .to_integer();
```

This matches the pattern already used elsewhere in the codebase for safety-critical conversions (e.g., `convert_l1_to_l2_gas_price_round_up`, `l1_gas_to_sierra_gas_amount_round_up`, `sierra_gas_to_l1_gas_amount_round_up`, and `calculate_resource_gas_cost` all use `.ceil().to_integer()`).

Add a test case with a non-round product, e.g. `prev=101, pct=90`, asserting that a transaction with `tx_price=90` is **rejected** (threshold should be 91, not 90).

### Proof of Concept

1. Operator configures `min_gas_price_percentage = 90`.
2. Previous block's L2 gas price is `101 FRI` (a typical non-round value from EIP-1559 dynamics).
3. Floored threshold = `floor(90 × 101 / 100)` = `floor(90.9)` = `90`.
4. Attacker submits an `InvokeV3` transaction with `AllResourceBounds { l2_gas: { max_price_per_unit: 90, max_amount: 1_210_000_000 }, ... }`.
5. `validate_tx_l2_gas_price_within_threshold` computes `threshold = 90`, checks `90 < 90` → false → **admits the transaction**.
6. True threshold is 91; the transaction should have been rejected.
7. The transaction enters the mempool and is sequenced, paying 90 FRI/gas instead of the required ≥91 FRI/gas, for a total underpayment of 1,210,000,000 FRI ≈ 1.21 STRK on a max-gas transaction.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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
