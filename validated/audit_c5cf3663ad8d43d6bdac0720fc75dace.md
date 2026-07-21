### Title
Gateway Stateful Validator Checks Only L2 Gas Price, Admitting Transactions with Zero L1/L1-Data Gas Prices That Always Fail at Blockifier Execution — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check validates only the L2 gas `max_price_per_unit` against the previous block's L2 gas price. It explicitly skips L1 gas and L1 data gas price validation. The blockifier's `check_fee_bounds`, however, enforces all three gas prices at execution time. An unprivileged sender can craft a V3 `AllResources` transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` that passes every gateway check and enters the mempool, but is guaranteed to fail at blockifier pre-validation with `MaxGasPriceTooLow`. Because the failure occurs before fee transfer, the sender pays nothing, enabling a free, repeatable mempool-pollution attack.

---

### Finding Description

**Gateway stateful path — `validate_resource_bounds`:**

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
            // ... only l2_gas.max_price_per_unit is checked ...
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
    Ok(())
}
``` [1](#0-0) 

The stateless validator also only checks `l2_gas.max_price_per_unit` and `l2_gas.max_amount`; it never inspects `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`: [2](#0-1) 

**Blockifier execution path — `check_fee_bounds`:**

At execution time, `check_fee_bounds` enforces all three gas prices against the current block's `NonzeroGasPrice` values:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(
        ResourceBoundsError::MaxGasPriceTooLow { ... }
    );
}
``` [3](#0-2) 

Because `actual_gas_price` is typed `NonzeroGasPrice`, its `.get()` is always `> 0`. A transaction with `l1_gas.max_price_per_unit = 0` or `l1_data_gas.max_price_per_unit = 0` will **always** fail this check.

**`perform_pre_validation_stage` ordering:**

```rust
Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;
if self.execution_flags.charge_fee {
    self.check_fee_bounds(tx_context)?;          // ← fails here
    verify_can_pay_committed_bounds(...)?;
}
``` [4](#0-3) 

The failure is a `TransactionPreValidationError`; the transactional state is rolled back, so no fee is charged to the sender.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker submits `AllResources` V3 invoke transactions with:
- `l1_gas.max_price_per_unit = 0`, `l1_gas.max_amount = large`
- `l1_data_gas.max_price_per_unit = 0`, `l1_data_gas.max_amount = large`
- `l2_gas.max_price_per_unit = min_gas_price` (passes stateless check), `l2_gas.max_amount = 1`

The total `max_possible_fee` is 1 (non-zero), satisfying the stateless zero-bounds guard. The stateful L2 price check passes. The transaction enters the mempool. The batcher picks it up; the blockifier rejects it at `check_fee_bounds` with `MaxGasPriceTooLow` for L1 and L1-data gas. The state rolls back; the attacker pays nothing. The cycle repeats indefinitely, polluting the mempool and wasting batcher/blockifier resources at zero cost to the attacker.

---

### Likelihood Explanation

**Likelihood: High.**

The attack requires no special privilege, no existing balance, and no knowledge of internal state. Any sender can craft such a transaction with a standard RPC call. The gap is explicitly acknowledged in the codebase with a TODO comment, confirming it is not guarded elsewhere.

---

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or add a parallel function) to also validate `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the corresponding previous-block gas prices, using the same percentage-threshold mechanism already applied to L2 gas. The TODO comment at line 358 already identifies this gap:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
```

Apply the threshold check to all three resources in the `AllResources` branch, and consider adding a non-zero floor check for L1 and L1-data gas prices in the stateless validator as a first line of defence.

---

### Proof of Concept

1. Construct a V3 invoke transaction with:
   ```
   resource_bounds = AllResources {
       l1_gas:      { max_amount: 1_000_000, max_price_per_unit: 0 },
       l1_data_gas: { max_amount: 1_000_000, max_price_per_unit: 0 },
       l2_gas:      { max_amount: 1,         max_price_per_unit: <min_gas_price> },
   }
   ```
2. Submit via `add_tx` to the gateway.
3. **Stateless check** (`validate_resource_bounds`): `max_possible_fee = 1 > 0` ✓; `l2_gas.max_price_per_unit >= min_gas_price` ✓; `l2_gas.max_amount <= max_l2_gas_amount` ✓. Passes.
4. **Stateful check** (`validate_tx_l2_gas_price_within_threshold`): only `l2_gas.max_price_per_unit` is compared to the previous block's L2 price. Passes.
5. Transaction is admitted to the mempool.
6. Batcher picks it up; blockifier calls `check_fee_bounds`:
   - `l1_gas.max_price_per_unit (0) < actual_l1_gas_price (NonzeroGasPrice)` → `MaxGasPriceTooLow` error.
7. `TransactionPreValidationError` is returned; state rolls back; no fee charged.
8. Repeat from step 1 with a new nonce. [5](#0-4) [6](#0-5)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-458)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
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
