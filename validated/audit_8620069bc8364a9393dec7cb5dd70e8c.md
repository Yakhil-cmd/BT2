### Title
Gateway Admits Transactions With Insufficient L1/L1DataGas Price Bounds That Will Always Fail Blockifier Pre-Validation - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check only validates the L2 gas price against the previous block's price. It explicitly skips validation for L1 gas and L1 data gas prices. A transaction with `l1_gas.max_price_per_unit = 0` (or any value below the current block's L1 gas price) passes all gateway checks, enters the mempool, and then unconditionally fails blockifier `check_fee_bounds` pre-validation when the batcher attempts to include it in a block. The transaction is never sequenced, yet the gateway accepted it as valid.

### Finding Description

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` only checks the L2 gas price:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(
    &self,
    tx_resource_bounds: ValidResourceBounds,
    previous_block_l2_gas_price: NonzeroGasPrice,
) -> StatefulTransactionValidatorResult<()> {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
            // ... only l2_gas price is checked ...
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
    Ok(())
}
``` [1](#0-0) 

The stateless validator similarly only checks `l2_gas.max_price_per_unit` and `l2_gas.max_amount`: [2](#0-1) 

In contrast, the blockifier's `check_fee_bounds` (called from `perform_pre_validation_stage`) validates **all three** gas prices against the actual block prices: [3](#0-2) 

The `perform_pre_validation_stage` is called unconditionally before any execution: [4](#0-3) 

**Attack path:**

1. Attacker submits a V3 `AllResources` transaction with:
   - `l2_gas.max_price_per_unit` ≥ current L2 gas price (passes stateless + stateful gateway checks)
   - `l2_gas.max_amount` ≥ 1 (passes `max_possible_fee != 0` check)
   - `l1_gas.max_price_per_unit = 0` (below actual L1 gas price — **not checked by gateway**)
2. Transaction passes `StatelessTransactionValidator::validate` and `StatefulTransactionValidator::extract_state_nonce_and_run_validations`.
3. Transaction is admitted to the mempool.
4. When the batcher calls `check_fee_bounds`, it fails with `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0, actual_gas_price: <current> }`.
5. Transaction is never included in any block.

The `max_possible_fee` guard in the stateless validator does not prevent this because it only requires the total fee to be non-zero — a transaction with non-zero L2 gas bounds but zero L1 gas price still passes: [5](#0-4) 

### Impact Explanation

**High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

The gateway accepts and forwards to the mempool transactions that are structurally guaranteed to fail blockifier pre-validation. These transactions occupy mempool capacity, consume gateway validation resources (including the CPU-heavy `__validate__` entry-point execution), and are never sequenced. An attacker can flood the mempool with such transactions at low cost (no fee is ever charged since the transactions never execute).

### Likelihood Explanation

Any unprivileged user can craft a V3 transaction with `l1_gas.max_price_per_unit = 0`. The gateway has no defense against this. The TODO comment in the source code (`// TODO(Arni): Consider running this validation for all gas prices.`) confirms the gap is known but unaddressed.

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or create a parallel function) to also validate `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the previous block's corresponding gas prices, mirroring the logic already applied to L2 gas. The stateless validator should similarly enforce a non-zero floor for `l1_gas.max_price_per_unit` when `l1_gas.max_amount > 0`.

### Proof of Concept

```
// Craft a transaction that passes all gateway checks but fails blockifier pre-validation:
resource_bounds = AllResourceBounds {
    l1_gas:      ResourceBounds { max_amount: 1000, max_price_per_unit: 0 },  // <-- zero price
    l2_gas:      ResourceBounds { max_amount: 1000, max_price_per_unit: <current_l2_price> },
    l1_data_gas: ResourceBounds { max_amount: 0,    max_price_per_unit: 0 },
}

// Gateway stateless check:
//   max_possible_fee(Tip::ZERO) = 0 + 1000*current_l2_price + 0 > 0  → PASS
//   l2_gas.max_price_per_unit >= min_gas_price                         → PASS
//   l2_gas.max_amount <= max_l2_gas_amount                             → PASS

// Gateway stateful check:
//   validate_tx_l2_gas_price_within_threshold: l2_gas price OK         → PASS
//   l1_gas.max_price_per_unit = 0 is NEVER checked                     → PASS

// Blockifier check_fee_bounds (at block-building time):
//   l1_gas.max_price_per_unit (0) < actual_l1_gas_price (e.g. 100)    → FAIL
//   → ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas, ... }
//   → Transaction dropped, never sequenced
``` [1](#0-0) [6](#0-5)

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
