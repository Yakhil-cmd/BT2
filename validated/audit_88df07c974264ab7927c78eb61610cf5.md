### Title
Gateway Stateful Validator Omits L1 and L1-Data Gas Price Checks for `AllResources` Transactions, Admitting Transactions That Fail Blockifier Pre-Validation — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check only validates the L2 gas price against the previous block's price. It silently skips L1 gas and L1-data gas price validation. The blockifier's `check_fee_bounds`, called during actual execution, checks **all three** gas prices against the current block's prices. An unprivileged user can craft a V3 (`AllResources`) transaction whose L2 gas price clears the gateway threshold while L1 and L1-data gas prices are zero, causing the transaction to be admitted to the mempool and then fail blockifier pre-validation — without paying any fee and without the nonce being permanently consumed.

---

### Finding Description

In `validate_resource_bounds` (line 223), the stateful validator calls `validate_tx_l2_gas_price_within_threshold` (line 237):

```rust
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
``` [1](#0-0) 

Inside `validate_tx_l2_gas_price_within_threshold` (line 358), the function explicitly carries a TODO and only inspects `l2_gas.max_price_per_unit`; the `L1Gas` arm performs **no check at all**:

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
            // ← l1_gas and l1_data_gas prices are never read
            ...
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
    Ok(())
}
``` [2](#0-1) 

The stateless validator's `validate_resource_bounds` also only enforces a floor on `l2_gas.max_price_per_unit` and a non-zero total fee; it never checks L1 or L1-data gas prices individually: [3](#0-2) 

By contrast, the blockifier's `check_fee_bounds` (called from `perform_pre_validation_stage`) iterates over **all three** resources and rejects the transaction if any `max_price_per_unit` is below the current block's actual gas price:

```rust
vec![
    (L1Gas,     l1_gas_resource_bounds,     minimal_gas_amount_vector.l1_gas,     *l1_gas_price),
    (L1DataGas, l1_data_gas_resource_bounds, minimal_gas_amount_vector.l1_data_gas, *l1_data_gas_price),
    (L2Gas,     l2_gas_resource_bounds,     minimal_gas_amount_vector.l2_gas,     *l2_gas_price),
]
// ...
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

`perform_pre_validation_stage` increments the nonce first, then calls `check_fee_bounds`; a pre-validation failure causes the entire transaction to be rejected (nonce rolled back, no fee charged): [5](#0-4) 

The mempool's `validate_tx` only checks nonce validity and fee-escalation rules against the existing pool; it does not inspect L1 or L1-data gas prices: [6](#0-5) 

---

### Impact Explanation

A transaction with:
- `l2_gas.max_price_per_unit ≥ previous_block_l2_gas_price × min_gas_price_percentage / 100` (clears gateway threshold)
- `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0`

passes every gateway and mempool check, occupies a mempool slot, is handed to the batcher, and then fails `check_fee_bounds` with `MaxGasPriceTooLow` for L1Gas and L1DataGas. The transaction is discarded without fee payment. An attacker can continuously flood the mempool with such transactions, exhausting mempool capacity and batcher CPU without cost.

**Impact category:** High — Mempool/gateway admission accepts invalid transactions before sequencing.

---

### Likelihood Explanation

The attack requires only a standard V3 RPC transaction with deliberately zeroed L1 and L1-data gas prices. No privileged access, special account, or contract deployment is needed. The condition is trivially constructable by any user.

---

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or rename it) to apply the same percentage-threshold check to `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` using the corresponding previous-block prices from `get_block_info().gas_prices`. The existing TODO at line 358 already acknowledges this gap. [7](#0-6) 

---

### Proof of Concept

1. Obtain `previous_block_l2_gas_price` and `min_gas_price_percentage` from the node config (both are observable).
2. Compute `threshold = previous_block_l2_gas_price × min_gas_price_percentage / 100`.
3. Submit an `InvokeV3` RPC transaction with:
   ```json
   "resource_bounds": {
     "l2_gas":      { "max_amount": "0x1000", "max_price_per_unit": "<threshold>" },
     "l1_gas":      { "max_amount": "0x0",    "max_price_per_unit": "0x0" },
     "l1_data_gas": { "max_amount": "0x0",    "max_price_per_unit": "0x0" }
   }
   ```
4. **Gateway stateless check** (`validate_resource_bounds`): passes — L2 gas price ≥ `min_gas_price`, total fee > 0.
5. **Gateway stateful check** (`validate_tx_l2_gas_price_within_threshold`): passes — L2 gas price ≥ threshold; L1/L1-data gas prices not examined.
6. **Mempool** (`validate_tx`): passes — nonce valid, no fee-escalation conflict.
7. **Batcher → blockifier** (`check_fee_bounds`): **fails** — `l1_gas.max_price_per_unit = 0 < actual_l1_gas_price` → `MaxGasPriceTooLow`; transaction rejected pre-validation, no fee charged, mempool slot consumed.
8. Repeat indefinitely to exhaust mempool capacity.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L223-241)
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
    }
```
