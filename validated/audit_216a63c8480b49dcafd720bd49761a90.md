### Title
Floor-Truncated L2 Gas Price Threshold Admits Below-Minimum Transactions at Gateway — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price by multiplying `previous_block_l2_gas_price` by `min_gas_price_percentage / 100` and calling `.to_integer()` on the resulting `Ratio`, which **truncates (floors)** the result. When the product is non-integer, the enforced threshold is strictly lower than the intended threshold, allowing a transaction whose L2 gas price is below the true minimum to pass gateway admission and enter the mempool.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 367–372:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← floor truncation
if tx_l2_gas_price.0 < threshold {
```

`num_rational::Ratio::to_integer()` returns the integer part (floor) of the rational number. When `min_gas_price_percentage × previous_block_l2_gas_price` is not evenly divisible by 100, the computed `threshold` is one unit lower than the true fractional threshold.

**Concrete example:**
- `min_gas_price_percentage = 50`, `previous_block_l2_gas_price = 101`
- True threshold = 50/100 × 101 = **50.5**
- Computed threshold = `floor(50.5)` = **50**
- A transaction with `tx_l2_gas_price = 50` satisfies `50 < 50` → **false** → admitted
- But 50 < 50.5, so it should be **rejected**

The same rounding gap occurs for any `min_gas_price_percentage` value that is not 100 (e.g., 80, 50, 10) whenever `previous_block_l2_gas_price` is not divisible by `100 / gcd(min_gas_price_percentage, 100)`.

**Call chain to the vulnerable check:**

`extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `validate_state_preconditions` → `validate_resource_bounds` → `validate_tx_l2_gas_price_within_threshold` [1](#0-0) 

The attacker-controlled field is `tx_resource_bounds.l2_gas.max_price_per_unit`, which is read directly from the submitted transaction without any sanitization before this check. [2](#0-1) 

The existing test suite only exercises round numbers (100, 50, 49, 51) where `previous_block_l2_gas_price = 100` and `min_gas_price_percentage ∈ {100, 50, 10}`, so `percentage × price` is always divisible by 100 and the truncation never fires. [3](#0-2) 

The default `min_gas_price_percentage` is 100, which means the threshold equals the previous block price exactly and no rounding occurs in the default configuration. The bug is latent and activates as soon as an operator sets a sub-100 percentage. [4](#0-3) 

### Impact Explanation

**High. Mempool/gateway admission accepts invalid transactions before sequencing.**

A transaction whose L2 gas price is below the operator-configured minimum fraction of the previous block's L2 gas price bypasses the gateway's price floor check and is admitted to the mempool. This undermines the spam-prevention and fee-market enforcement that `min_gas_price_percentage` is designed to provide, allowing an attacker to flood the mempool with artificially cheap transactions that the sequencer is then obligated to process.

### Likelihood Explanation

**Low.** The default `min_gas_price_percentage` is 100, which is immune to the rounding issue. The bug only manifests when an operator deliberately sets a sub-100 percentage **and** the current L2 gas price is not divisible by `100 / gcd(percentage, 100)`. In practice, L2 gas prices are large integers (e.g., in the billions of FRI), so the rounding gap is exactly 1 unit — a negligible economic difference per transaction. However, the invariant is still broken and the check can be bypassed deterministically by any user who observes the current gas price.

### Recommendation

Replace `.to_integer()` (floor) with ceiling division so the enforced threshold is never lower than the true fractional threshold:

```rust
// Before (floor — threshold can be below true minimum):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();

// After (ceiling — threshold is always >= true minimum):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()
    .to_integer();
```

`num_rational::Ratio::ceil()` returns the smallest integer ≥ the rational value, which is the correct rounding direction for a minimum-price guard. Add a test case with an odd `previous_block_l2_gas_price` (e.g., 101) and a non-100 percentage to cover this path.

### Proof of Concept

```
min_gas_price_percentage = 50
previous_block_l2_gas_price = 101

threshold (current code) = floor(50/100 * 101) = floor(50.5) = 50
threshold (correct)      = ceil(50/100 * 101)  = ceil(50.5)  = 51

Submit transaction with tx_l2_gas_price = 50:
  Current check:  50 < 50  → false → ADMITTED  ← wrong
  Correct check:  50 < 51  → true  → REJECTED  ← correct
```

A user submitting an `AllResources` V3 invoke transaction with `l2_gas.max_price_per_unit = floor(min_gas_price_percentage/100 * prev_price)` will pass `validate_tx_l2_gas_price_within_threshold` and proceed through `run_validate_entry_point` into the mempool, bypassing the intended price floor by exactly 1 unit whenever the true threshold is non-integer. [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-243)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
    }

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L365-372)
```rust
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
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

**File:** crates/apollo_gateway_config/src/config.rs (L286-299)
```rust
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
```
