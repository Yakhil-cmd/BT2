### Title
Gateway Stateful Validator Checks Only L2 Gas Price, Admitting Transactions With Insufficient L1/L1-Data Gas Prices That Fail During Blockifier Pre-Validation - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The stateful gateway validator's resource-bounds check validates only the L2 gas price against the previous block's price. L1 gas price and L1 data gas price are never checked. The blockifier's `check_fee_bounds`, called during `perform_pre_validation_stage`, checks **all three** gas prices and rejects transactions whose `max_price_per_unit` is below the current block price. This gap allows an attacker to craft transactions that pass every gateway admission check but are unconditionally rejected during blockifier pre-validation, polluting the mempool with permanently-invalid transactions.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads only `strk_gas_prices.l2_gas_price` from the previous block and delegates to `validate_tx_l2_gas_price_within_threshold`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn validate_resource_bounds(...) {
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

`validate_tx_l2_gas_price_within_threshold` explicitly skips L1Gas transactions entirely and, for `AllResources`, only inspects `l2_gas.max_price_per_unit`. The developer TODO acknowledges the gap:

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
            // ... only l2_gas checked ...
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
    Ok(())
}
``` [2](#0-1) 

The stateless validator similarly only checks `l2_gas.max_price_per_unit` against a static floor; L1 and L1-data gas prices are unconstrained: [3](#0-2) 

In contrast, the blockifier's `check_fee_bounds` (called unconditionally inside `perform_pre_validation_stage` when `charge_fee` is true) iterates over **all three** resources and rejects the transaction if any `max_price_per_unit` is below the block's actual gas price:

```rust
// crates/blockifier/src/transaction/account_transaction.rs
ValidResourceBounds::AllResources(AllResourceBounds {
    l1_gas: l1_gas_resource_bounds,
    l2_gas: l2_gas_resource_bounds,
    l1_data_gas: l1_data_gas_resource_bounds,
}) => {
    vec![
        (L1Gas,     l1_gas_resource_bounds,     ..., *l1_gas_price),
        (L1DataGas, l1_data_gas_resource_bounds, ..., *l1_data_gas_price),
        (L2Gas,     l2_gas_resource_bounds,      ..., *l2_gas_price),
    ]
}
// ...
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

`perform_pre_validation_stage` is the first thing called during execution: [5](#0-4) 

A `MaxGasPriceTooLow` error from `check_fee_bounds` propagates as a `TransactionPreValidationError`, causing the transaction to be **rejected** (not reverted), meaning no fee is charged and the transaction is discarded by the batcher.

### Impact Explanation

Any unprivileged user can submit an `AllResources` V3 transaction with:
- `l2_gas.max_price_per_unit` ≥ the stateful threshold (passes both gateway checks)
- `l1_gas.max_price_per_unit = 0` (never checked by either gateway validator)
- `l2_gas.max_amount > 0` (so `max_possible_fee > 0`, passes the stateless zero-bounds check)

Such a transaction clears every gateway admission gate and enters the mempool. When the batcher pulls it for block inclusion, `check_fee_bounds` immediately rejects it with `MaxGasPriceTooLow` for L1 gas. The batcher discards the transaction and the mempool slot is wasted. An attacker can repeat this at scale (one transaction per nonce slot, up to `max_allowed_nonce_gap = 200` per account) to fill mempool queues with permanently-invalid entries, degrading throughput for legitimate transactions.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The trigger requires only a well-formed V3 transaction with `l1_gas.max_price_per_unit = 0`. No privileged access, special account, or race condition is needed. The L1 gas price on Starknet is always non-zero in production, so every such transaction will fail the blockifier check deterministically. The attack is cheap (no fee is charged on rejection) and repeatable.

### Recommendation

Extend `validate_resource_bounds` (or `validate_tx_l2_gas_price_within_threshold`) to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the corresponding prices from the previous block, mirroring the three-resource loop already present in `check_fee_bounds`. The existing TODO comment at line 358 already flags this gap.

### Proof of Concept

1. Obtain the current `strk_gas_prices.l1_gas_price` from the latest block header (e.g., via `starknet_getBlockWithTxHashes`).
2. Craft a V3 Invoke transaction with:
   - `l2_gas = { max_amount: 1, max_price_per_unit: <threshold> }` — passes stateful L2 check
   - `l1_gas = { max_amount: 1, max_price_per_unit: 0 }` — not checked by gateway
   - `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }` — not checked by gateway
3. Submit via the gateway RPC. The transaction passes `StatelessTransactionValidator::validate` (L2 price ≥ floor, `max_possible_fee > 0`) and `StatefulTransactionValidator::validate_resource_bounds` (only L2 price checked).
4. The transaction is accepted into the mempool.
5. When the batcher executes it, `check_fee_bounds` fires `MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0, actual_gas_price: <non-zero> }` and the transaction is rejected without fee charge.
6. Repeat with nonce+1 up to `max_allowed_nonce_gap` (200) to saturate the account's mempool queue with permanently-invalid entries.

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
