### Title
Gateway Stateful Validator Only Checks L2 Gas Price, Admitting Transactions With Insufficient L1/L1-Data Gas Prices - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` only validates the transaction's L2 gas price against the previous block's threshold. It never validates the L1 gas price or L1 data gas price. Transactions with zero or arbitrarily low L1/L1-data gas prices pass gateway admission and enter the mempool, but are guaranteed to fail at blockifier execution time when `check_fee_bounds` enforces all three gas-price bounds.

### Finding Description

`validate_resource_bounds` reads only `strk_gas_prices.l2_gas_price` from the previous block and delegates to `validate_tx_l2_gas_price_within_threshold`: [1](#0-0) 

Inside `validate_tx_l2_gas_price_within_threshold`, only `l2_gas.max_price_per_unit` is compared against the threshold. For `ValidResourceBounds::L1Gas` the function explicitly returns `Ok(())` with no check at all. For `ValidResourceBounds::AllResources`, `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never read: [2](#0-1) 

The developer-authored TODO on line 358 acknowledges the gap: `// TODO(Arni): Consider running this validation for all gas prices.`

In contrast, the blockifier's `check_fee_bounds` — called during actual execution — enforces all three gas prices for `AllResources` transactions: [3](#0-2) 

The result is a split invariant: the gateway admits a transaction that the blockifier will unconditionally reject.

### Impact Explanation

Any unprivileged user can submit a V3 (`AllResources`) transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0`. The gateway's stateful validator passes it (L2 gas price is fine), the mempool accepts it, and the batcher wastes execution resources before discarding it with `InsufficientResourceBounds`. This is a repeatable, low-cost mempool-flooding vector: the attacker pays nothing (the transaction never executes) while the sequencer pays CPU and mempool-slot costs for every such submission.

Impact: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The trigger requires only a standard V3 transaction with deliberately low L1 gas bounds. No privileged access, no special contract, no race condition. The check is simply absent.

### Recommendation

Extend `validate_resource_bounds` to also fetch `strk_gas_prices.l1_gas_price` and `strk_gas_prices.l1_data_gas_price` from the previous block and apply the same percentage-threshold check to `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` for `AllResources` transactions. The existing `min_gas_price_percentage` config field can be reused. The `ValidResourceBounds::L1Gas` arm should similarly validate `l1_gas.max_price_per_unit` against the previous block's L1 gas price.

### Proof of Concept

1. Obtain the current L2 gas price from the previous block (e.g. 10 Gwei).
2. Submit a V3 invoke transaction with:
   - `l2_gas.max_price_per_unit = 10 Gwei` (passes the L2 check)
   - `l1_gas.max_price_per_unit = 0`
   - `l1_data_gas.max_price_per_unit = 0`
3. `StatefulTransactionValidator::validate_resource_bounds` calls `validate_tx_l2_gas_price_within_threshold`, which only checks `l2_gas.max_price_per_unit`. The function returns `Ok(())`.
4. The transaction is admitted to the mempool.
5. When the batcher calls `AccountTransaction::perform_pre_validation_stage` → `check_fee_bounds`, the blockifier compares `l1_gas.max_price_per_unit (0)` against the block's actual L1 gas price and returns `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas, … }`, rejecting the transaction.
6. Repeat indefinitely to exhaust mempool capacity at zero cost. [4](#0-3) [5](#0-4)

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
