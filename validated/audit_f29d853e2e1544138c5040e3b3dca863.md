### Title
Gateway Stateful Validator Admits Transactions with Zero L1/L1-Data Gas Price That Inevitably Fail at Blockifier Execution — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful `validate_resource_bounds` only checks the **L2 gas price** against the previous block's L2 gas price. It never validates `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`. The blockifier's `check_fee_bounds`, called during `perform_pre_validation_stage`, checks **all three** gas prices against the block's actual prices. A transaction with `l1_gas.max_price_per_unit = 0` passes every gateway check and enters the mempool, but will always be rejected by the blockifier with `MaxGasPriceTooLow` — without charging any fee to the sender.

---

### Finding Description

**Stateless validator** (`crates/apollo_gateway/src/stateless_transaction_validator.rs`, lines 56–88):

- Rejects if total `max_possible_fee(Tip::ZERO) == 0`.
- Rejects if `l2_gas.max_price_per_unit < min_gas_price`.
- **No check on `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`.** [1](#0-0) 

**Stateful validator** (`crates/apollo_gateway/src/stateful_transaction_validator.rs`, lines 223–390):

`validate_resource_bounds` reads only `strk_gas_prices.l2_gas_price` from the previous block and calls `validate_tx_l2_gas_price_within_threshold`. The function explicitly skips L1 and L1-data gas prices, with an acknowledged TODO:

```
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...)
``` [2](#0-1) [3](#0-2) 

**Blockifier pre-validation** (`crates/blockifier/src/transaction/account_transaction.rs`, lines 374–476):

`check_fee_bounds` iterates over all three resources and enforces:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    // MaxGasPriceTooLow
}
```

for `L1Gas`, `L1DataGas`, and `L2Gas` independently. If `l1_gas.max_price_per_unit = 0` and the block's L1 gas price is non-zero (which it always is in production), the transaction fails here. [4](#0-3) 

**Attack path:**

1. Craft a V3 `AllResources` transaction with `l2_gas.max_price_per_unit ≥ min_gas_price` (passes stateless check), `l2_gas.max_price_per_unit ≥ threshold` (passes stateful check), and `l1_gas.max_price_per_unit = 0`, `l1_data_gas.max_price_per_unit = 0`.
2. Both gateway validators pass. Transaction enters the mempool.
3. Batcher calls `perform_pre_validation_stage` → `check_fee_bounds`. The blockifier compares `l1_gas.max_price_per_unit = 0` against the block's actual L1 gas price (always > 0) and returns `MaxGasPriceTooLow`.
4. Transaction fails at pre-validation. **No fee is charged** (fee enforcement only applies after this stage succeeds). The nonce increment from `handle_nonce` is rolled back via the cached state. [5](#0-4) 

---

### Impact Explanation

The gateway's partial price validation creates a permanent admission gap: any transaction with a valid L2 gas price but zero L1 or L1-data gas price passes all gateway checks and enters the mempool, yet will always be rejected by the blockifier at execution time. Because the failure occurs at `perform_pre_validation_stage` before fee transfer, the sender pays nothing. An attacker can flood the mempool with such transactions at zero cost (beyond the cost of submitting them), wasting batcher computation and mempool capacity.

**Impact category:** High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.

---

### Likelihood Explanation

The attack requires only crafting a standard V3 transaction with `l1_gas.max_price_per_unit = 0`. No privileged access, special account, or race condition is needed. The TODO comment in the source confirms the gap is known but unaddressed. Any unprivileged user can trigger this.

---

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or create a parallel function) to also validate `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the previous block's corresponding STRK prices, using the same `min_gas_price_percentage` threshold already applied to L2 gas. The existing TODO comment at line 358 of `stateful_transaction_validator.rs` already identifies this gap. [3](#0-2) [6](#0-5) 

---

### Proof of Concept

```
// Craft a V3 AllResources invoke transaction:
resource_bounds = AllResourceBounds {
    l2_gas: ResourceBounds {
        max_amount:        1_000_000,
        max_price_per_unit: 8_000_000_000,  // >= min_gas_price (passes stateless)
                                             // >= threshold (passes stateful)
    },
    l1_gas: ResourceBounds {
        max_amount:        1_000_000,
        max_price_per_unit: 0,               // NOT checked by gateway
    },
    l1_data_gas: ResourceBounds {
        max_amount:        1_000_000,
        max_price_per_unit: 0,               // NOT checked by gateway
    },
}

// Gateway stateless check:
//   max_possible_fee(Tip::ZERO) = 8_000_000_000 * 1_000_000 > 0  → PASS
//   l2_gas.max_price_per_unit >= min_gas_price                    → PASS
//   l1_gas.max_price_per_unit not checked                         → PASS

// Gateway stateful check:
//   validate_tx_l2_gas_price_within_threshold:
//     tx_l2_gas_price (8e9) >= threshold (prev_block_l2 * %)      → PASS
//   l1_gas.max_price_per_unit not checked                         → PASS

// Transaction admitted to mempool.

// Batcher executes → perform_pre_validation_stage → check_fee_bounds:
//   actual_l1_gas_price (e.g. 100_000_000_000) > 0 = max_price_per_unit
//   → MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0, actual: 100e9 }
//   → TransactionPreValidationError
//   → No fee charged, nonce rolled back, transaction dropped.
```

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L64-76)
```rust
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
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-458)
```rust
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
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
