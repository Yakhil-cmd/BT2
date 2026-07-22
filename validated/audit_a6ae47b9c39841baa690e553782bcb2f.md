### Title
Gateway Validates Only L2 Gas Price Against Threshold, Admitting Transactions With Zero L1/L1DataGas Price Into the Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs` and `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

Both the stateless and stateful gateway validators check only the **L2 gas price** against a configured minimum/threshold. The L1 gas price and L1 data gas price fields of an `AllResources` (V3) transaction are never validated at the gateway level. A transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` but a valid L2 gas price passes all gateway checks and is admitted to the mempool. The blockifier's `check_fee_bounds`, which runs during block production, checks all three gas prices against the block's actual prices and rejects such a transaction with `MaxGasPriceTooLow` for L1 gas — but only after it has already been admitted.

---

### Finding Description

**Stateless validator** (`validate_resource_bounds`):

```rust
// Only L2 gas price is checked:
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

L1 gas price and L1 data gas price are never compared against `min_gas_price`. [1](#0-0) 

**Stateful validator** (`validate_tx_l2_gas_price_within_threshold`):

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...) {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
            // threshold computed from previous_block_l2_gas_price only
            if tx_l2_gas_price.0 < threshold { return Err(...); }
        }
        ValidResourceBounds::L1Gas(_) => { /* No validation */ }
    }
}
```

The function name and the TODO comment both confirm that L1 gas price and L1 data gas price are intentionally skipped — but this creates the gap. [2](#0-1) 

**Blockifier's `check_fee_bounds`** (runs during block production, not at gateway admission):

```rust
// Checks ALL three resources:
vec![
    (L1Gas,     l1_gas_resource_bounds,     ..., *l1_gas_price),
    (L1DataGas, l1_data_gas_resource_bounds,..., *l1_data_gas_price),
    (L2Gas,     l2_gas_resource_bounds,     ..., *l2_gas_price),
]
// For each:
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    push MaxGasPriceTooLow { ... }
}
``` [3](#0-2) 

This is called from `perform_pre_validation_stage` only during blockifier execution, not at gateway admission time. [4](#0-3) 

The `StatefulTransactionValidatorConfig` documents the gap explicitly — `validate_resource_bounds` is described as ensuring "the max **L2** gas price exceeds (a configurable percentage of) the base gas price of the previous block," with no mention of L1 or L1 data gas. [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker submits a V3 (`AllResources`) transaction with:
- `l2_gas.max_price_per_unit` ≥ `min_gas_price` and ≥ threshold (passes both gateway checks)
- `l1_gas.max_price_per_unit = 0` (no gateway check)
- `l1_data_gas.max_price_per_unit = 0` (no gateway check)
- `l2_gas.max_amount > 0` (ensures `max_possible_fee > 0`, passing the zero-bounds check)

The transaction passes all gateway validation and is admitted to the mempool. When the batcher attempts to include it in a block, `check_fee_bounds` rejects it with `InsufficientResourceBounds { MaxGasPriceTooLow { resource: L1Gas } }` because `0 < actual_l1_gas_price`. The transaction is definitively invalid but was admitted as valid. An attacker can repeat this at scale to fill the mempool with permanently-unexecutable transactions at zero cost (no fee is ever charged since the transaction never executes).

---

### Likelihood Explanation

Any unprivileged user can craft a V3 transaction with zero L1 gas price. No special account state, privileged access, or race condition is required. The attack is trivially repeatable up to the mempool's capacity limit, and each submission passes all gateway checks deterministically.

---

### Recommendation

Extend both validators to check L1 gas price and L1 data gas price against their respective minimums, mirroring the existing L2 gas price check:

1. **Stateless validator** (`validate_resource_bounds`): Add checks for `resource_bounds.l1_gas.max_price_per_unit` and `resource_bounds.l1_data_gas.max_price_per_unit` against a configured `min_l1_gas_price` / `min_l1_data_gas_price`.

2. **Stateful validator** (`validate_tx_l2_gas_price_within_threshold`): Rename to `validate_tx_gas_prices_within_threshold` and add analogous threshold checks for L1 gas price and L1 data gas price using the previous block's `l1_gas_price` and `l1_data_gas_price` (already available in `block_info.gas_prices`). [6](#0-5) 

---

### Proof of Concept

1. Obtain the previous block's L2 gas price `P_l2` (e.g., via RPC).
2. Construct a V3 invoke transaction with:
   - `l2_gas = { max_amount: 1, max_price_per_unit: P_l2 }` (meets threshold)
   - `l1_gas = { max_amount: 0, max_price_per_unit: 0 }` (zero price, no gateway check)
   - `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }` (zero price, no gateway check)
3. Submit via the gateway RPC endpoint.
4. **Expected (buggy) result**: Transaction passes `validate_resource_bounds` (stateless) and `validate_tx_l2_gas_price_within_threshold` (stateful), enters the mempool.
5. **Blockifier result**: When the batcher pulls this transaction, `check_fee_bounds` fires `MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0, actual_gas_price: <block_l1_price> }` and rejects it.
6. Repeat with fresh nonces to continuously fill the mempool with permanently-invalid transactions.

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
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
