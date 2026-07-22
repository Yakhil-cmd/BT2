### Title
Threshold Rounds to Zero in `validate_tx_l2_gas_price_within_threshold`, Admitting Below-Minimum-Price Transactions — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price as `floor(min_gas_price_percentage / 100 × previous_block_l2_gas_price)`. When `previous_block_l2_gas_price < 100 / min_gas_price_percentage` (e.g., price = 1 FRI with percentage = 50), integer truncation via `Ratio::to_integer()` collapses the threshold to **0**. The subsequent guard `tx_l2_gas_price.0 < threshold` is then `x < 0` on a `u128`, which is always `false`, so **every** transaction passes regardless of its offered L2 gas price — including transactions with `max_price_per_unit = 0`.

---

### Finding Description

The vulnerable code is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 367-372
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← floors the rational; can produce 0
if tx_l2_gas_price.0 < threshold {   // ← always false when threshold == 0
    return Err(...);
}
```

`Ratio::to_integer()` truncates toward zero. For any `previous_block_l2_gas_price` value `p` and percentage `pct`:

```
threshold = floor(pct / 100 × p)
```

Whenever `p < 100 / pct` (e.g., `p = 1`, `pct = 50` → `threshold = floor(0.5) = 0`; or `p = 1`, `pct = 99` → `threshold = floor(0.99) = 0`), the threshold collapses to zero. Because `tx_l2_gas_price.0` is a `u128`, the comparison `tx_l2_gas_price.0 < 0` is vacuously false, and the function returns `Ok(())` unconditionally.

This is the direct Sequencer analog of the external rounding-to-zero bug: a proportional share calculation silently produces zero, making a guard that should reject certain inputs permanently ineffective.

The `previous_block_l2_gas_price` is read from the latest committed block's `strk_gas_prices.l2_gas_price` field. The fee-market code enforces a minimum via `VersionedConstants::min_gas_price`, but that minimum can be as low as 1 FRI (the test suite explicitly uses `LOW_OVERRIDE_L2_GAS_PRICE = 25` and notes that `LOW_OVERRIDE_L2_GAS_PRICE_FAIL = 1` causes block-build failure, not a hard floor on the stored price). During bootstrap, price overrides, or after a period of very low usage, the stored price can be small enough to trigger the rounding.

The stateless validator has a separate static `min_gas_price` check, but:
- It is a fixed config value, not tied to the dynamic block price.
- It can be set to 0 or disabled via `validate_resource_bounds = false`.
- Even when non-zero, it does not protect against the rounding error for non-zero but below-threshold prices (e.g., `pct = 50`, `p = 3` → intended threshold 1.5, actual threshold 1; a tx with price 1 passes when it should not). [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

When the threshold collapses to zero, the gateway's stateful L2 gas price guard is completely bypassed. An attacker can submit `AllResources` V3 transactions with `l2_gas.max_price_per_unit = 0` (or any value below the intended threshold) and have them admitted to the mempool. These transactions carry a committed fee of zero for L2 gas, so the sequencer cannot collect the intended minimum fee for L2 execution resources. At scale this enables fee-free spam that saturates the mempool and block capacity. [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

The default `min_gas_price_percentage` is **100**, which makes `threshold = previous_block_l2_gas_price` (no rounding loss). The bug is latent until an operator lowers `min_gas_price_percentage` below 100 — a documented, intended configuration option (the field comment says "E.g., 80 to require 80% of threshold"). Once set to any value < 100, the rounding error activates whenever the previous block's L2 gas price is small. The L2 gas price can reach low values during bootstrap, after a price override, or during low-congestion periods where the EIP-1559 formula drives it toward `min_gas_price`. [5](#0-4) [6](#0-5) 

---

### Recommendation

Replace the flooring `to_integer()` with a ceiling division so the threshold is never weaker than intended:

```rust
// Before (floors — can produce 0):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();

// After (ceiling — threshold is always >= intended value):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .ceil()
    .to_integer();
```

`Ratio::ceil()` is available in `num_rational` and rounds up, ensuring that even a fractional threshold (e.g., 0.5) becomes 1 rather than 0. This mirrors the pattern already used in `convert_l1_to_l2_gas_price_round_up` and `l1_gas_to_sierra_gas_amount_round_up` elsewhere in the codebase. [7](#0-6) 

---

### Proof of Concept

Configuration: `min_gas_price_percentage = 50`, previous block `l2_gas_price = 1 FRI`.

```
threshold = floor(Ratio(50, 100) × 1) = floor(0.5) = 0
```

Submit a V3 `INVOKE` transaction with:
```json
"resource_bounds": {
  "l2_gas": { "max_amount": "0x100000", "max_price_per_unit": "0x0" },
  "l1_gas": { "max_amount": "0x1",      "max_price_per_unit": "0x1" },
  "l1_data_gas": { "max_amount": "0x1", "max_price_per_unit": "0x1" }
}
```

- Stateless check: `max_possible_fee(Tip::ZERO)` is non-zero (l1_gas contributes), so `ZeroResourceBounds` is not triggered. `l2_gas.max_price_per_unit = 0 >= min_gas_price` if `min_gas_price = 0`.
- Stateful check: `tx_l2_gas_price.0 (= 0) < threshold (= 0)` → `false` → `Ok(())`.

The transaction is admitted to the mempool with zero committed L2 gas fee. [1](#0-0) [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L103-115)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L56-88)
```rust
    fn validate_resource_bounds(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        if !self.config.validate_resource_bounds {
            return Ok(());
        }

        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }

        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }

        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L270-286)
```rust
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
