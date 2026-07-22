### Title
Gateway Stateful Validator Admits Transactions with Insufficient L1/L1DataGas Price Bounds That Will Inevitably Fail at Execution - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check validates only the L2 gas `max_price_per_unit` against the previous block's L2 gas price. L1 gas and L1 data gas `max_price_per_unit` fields are never checked against the current or previous block's prices at admission time. A transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` (but a non-zero L2 gas bound) passes both stateless and stateful gateway validation and enters the mempool, only to be rejected by the blockifier's `check_fee_bounds` at execution time with `MaxGasPriceTooLow`. The codebase itself acknowledges this gap with a TODO comment directly above the incomplete function.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads only the previous block's L2 gas price and delegates to `validate_tx_l2_gas_price_within_threshold`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn validate_resource_bounds(&self, executable_tx: &ExecutableTransaction)
    -> StatefulTransactionValidatorResult<()>
{
    if self.config.validate_resource_bounds {
        // TODO(Arni): getnext_l2_gas_price from the block header.
        let previous_block_l2_gas_price = self
            .gateway_fixed_block_state_reader
            .get_block_info().await?
            .gas_prices.strk_gas_prices.l2_gas_price;
        self.validate_tx_l2_gas_price_within_threshold(
            executable_tx.resource_bounds(),
            previous_block_l2_gas_price,
        )?;
    }
    Ok(())
}
``` [1](#0-0) 

Inside `validate_tx_l2_gas_price_within_threshold`, only `l2_gas.max_price_per_unit` is compared to the threshold. The `L1Gas` arm is explicitly a no-op, and `AllResources` only reads `l2_gas`:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...) {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
            // ... threshold check on l2_gas only ...
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
}
``` [2](#0-1) 

The stateless validator similarly only checks `l2_gas.max_price_per_unit` against a static `min_gas_price` config value, and `l2_gas.max_amount` against a cap. No L1 or L1DataGas price floor is enforced: [3](#0-2) 

At execution time, the blockifier's `check_fee_bounds` compares **all three** `max_price_per_unit` fields against the actual block gas prices:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(
        ResourceBoundsError::MaxGasPriceTooLow { ... }
    );
}
``` [4](#0-3) 

This check covers L1Gas, L1DataGas, and L2Gas for `AllResources` transactions: [5](#0-4) 

**Attack path**: An unprivileged user submits a V3 `AllResources` transaction with:
- `l1_gas.max_price_per_unit = 0`
- `l1_data_gas.max_price_per_unit = 0`
- `l2_gas.max_price_per_unit = current_l2_gas_price` (passes L2 threshold check)
- `l2_gas.max_amount > 0` (passes zero-fee check)

Both gateway validators accept this transaction. It enters the mempool. When the batcher picks it up and the blockifier runs `perform_pre_validation_stage`, `check_fee_bounds` immediately rejects it with `InsufficientResourceBounds { errors: [MaxGasPriceTooLow { resource: L1Gas, ... }] }`. [6](#0-5) 

### Impact Explanation

The gateway's purpose is to filter transactions that will fail before they consume mempool and batcher resources. By admitting transactions with `l1_gas.max_price_per_unit = 0` (or any value below the current L1 gas price, which is always `NonzeroGasPrice`), the gateway accepts transactions that are **guaranteed to fail** at blockifier pre-validation. This matches:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

The mempool can be flooded with zero-cost-to-submit transactions that will never execute, consuming mempool slots and batcher execution cycles. Users receive no early rejection signal at submission time for the L1/L1DataGas price dimension.

### Likelihood Explanation

The trigger requires only a standard V3 transaction submission with deliberately low L1/L1DataGas price bounds. No privileged access, special account, or chain state is required. The TODO comment in the production source (`// TODO(Arni): Consider running this validation for all gas prices.`) confirms the gap is known but unaddressed. [7](#0-6) 

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or create a parallel function) to also validate `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the previous block's corresponding STRK gas prices, applying the same `min_gas_price_percentage` threshold. The previous block's L1 and L1DataGas prices are already available from `gateway_fixed_block_state_reader.get_block_info()` (the same call already made for L2 gas). [8](#0-7) 

### Proof of Concept

```rust
// Construct a V3 AllResources transaction that passes all gateway checks
// but fails blockifier pre-validation.
let resource_bounds = ValidResourceBounds::AllResources(AllResourceBounds {
    l1_gas: ResourceBounds {
        max_amount: GasAmount(1000),
        max_price_per_unit: GasPrice(0), // Zero: below any NonzeroGasPrice
    },
    l1_data_gas: ResourceBounds {
        max_amount: GasAmount(1000),
        max_price_per_unit: GasPrice(0), // Zero: below any NonzeroGasPrice
    },
    l2_gas: ResourceBounds {
        max_amount: GasAmount(1_000_000),
        max_price_per_unit: GasPrice(current_l2_gas_price), // Passes L2 check
    },
});

// Step 1: Gateway stateless validation passes (total fee > 0 via l2_gas).
// Step 2: Gateway stateful validate_resource_bounds passes (only L2 price checked).
// Step 3: Transaction enters mempool.
// Step 4: Blockifier check_fee_bounds fires:
//   InsufficientResourceBounds {
//     errors: [MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0,
//              actual_gas_price: <NonzeroGasPrice> }]
//   }
// Transaction is rejected at execution, never sequenced.
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-425)
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
```
