### Title
Gateway stateful validator checks only L2 gas price threshold, allowing transactions with zero L1/L1-data gas price to bypass admission — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `validate_resource_bounds` function in the stateful gateway validator calls `validate_tx_l2_gas_price_within_threshold`, which only validates the L2 gas price against the previous block's L2 gas price. It silently skips the equivalent check for `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit`. A transaction carrying `AllResourceBounds` with `l1_gas.max_price_per_unit = 0` passes every gateway check and enters the mempool, where it will be executed by the blockifier and fail at `check_fee_bounds` — wasting sequencer resources and constituting a reachable admission of an invalid transaction.

### Finding Description
`StatefulTransactionValidator::validate_resource_bounds` fetches the previous block's L2 gas price and delegates to `validate_tx_l2_gas_price_within_threshold`: [1](#0-0) 

That helper function carries an explicit TODO acknowledging the gap and only inspects `l2_gas.max_price_per_unit`: [2](#0-1) 

The stateless validator's `validate_resource_bounds` has the same shape: it checks `l2_gas.max_price_per_unit` against a static `min_gas_price` floor and `l2_gas.max_amount` against `max_l2_gas_amount`, but never touches `l1_gas` or `l1_data_gas` price fields: [3](#0-2) 

The analog to the external report is exact: the external loop was supposed to update `sumOfExchangeWeights` for **every** exchange but only updated **one** exchange N times. Here, the validation is supposed to enforce a minimum price threshold for **every** resource type (L1 gas, L2 gas, L1 data gas) but only enforces it for **one** resource type (L2 gas), leaving the other two unchecked.

The blockifier's `check_fee_bounds` does enforce all three prices at execution time: [4](#0-3) 

However, that check runs **inside** the sequencer's block-building loop, after the transaction has already been admitted to the mempool. The gateway's purpose is to reject such transactions before they consume sequencer resources.

### Impact Explanation
An unprivileged user submits an `InvokeV3` transaction with `AllResourceBounds` where `l1_gas.max_price_per_unit = 0` and `l2_gas.max_price_per_unit` is set to a valid value above the L2 threshold. Both the stateless and stateful gateway validators pass the transaction. It enters the mempool. During block building the blockifier calls `perform_pre_validation_stage` → `check_fee_bounds`, which compares `l1_gas.max_price_per_unit` (0) against the block's actual L1 gas price and returns `InsufficientResourceBounds`. The transaction is rejected at execution, but only after consuming sequencer CPU and mempool slots. Repeated at scale this is a low-cost DoS against the admission pipeline.

Impact: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

### Likelihood Explanation
The attack requires no privilege, no special account, and no on-chain state. Any caller of `POST /add_transaction` can craft the payload. The only cost is the RPC call itself.

### Recommendation
Extend `validate_tx_l2_gas_price_within_threshold` (or rename it and add sibling checks) to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against their respective previous-block prices, mirroring the three-resource loop already present in `check_fee_bounds`. The existing TODO comment at line 358 already flags this gap: [5](#0-4) 

### Proof of Concept
1. Construct an `RpcInvokeTransactionV3` with:
   - `l2_gas: ResourceBounds { max_price_per_unit: <value ≥ threshold>, max_amount: <any> }`
   - `l1_gas: ResourceBounds { max_price_per_unit: 0, max_amount: <any> }`
   - `l1_data_gas: ResourceBounds { max_price_per_unit: 0, max_amount: <any> }`
2. Submit via `POST /add_transaction`.
3. Stateless validator passes: `l2_gas.max_price_per_unit ≥ min_gas_price` ✓; zero-fee check passes because L2 fee is non-zero ✓.
4. Stateful validator passes: `validate_tx_l2_gas_price_within_threshold` only checks `l2_gas.max_price_per_unit` ✓.
5. Transaction enters the mempool.
6. During block building, `check_fee_bounds` compares `l1_gas.max_price_per_unit = 0` against the block's L1 gas price and returns `InsufficientResourceBounds { resource: L1Gas, … }`, rejecting the transaction — but only after it has already been processed by the sequencer.

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-426)
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
```
