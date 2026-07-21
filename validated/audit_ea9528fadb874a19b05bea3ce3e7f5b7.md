### Title
Gateway Admits `AllResources` V3 Transactions with Zero L1/L1-Data Gas Price That Blockifier Deterministically Rejects - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful and stateless resource-bound validators check **only the L2 gas price** against the current network price. They do not check `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit` at all. The blockifier's `check_fee_bounds`, called during `perform_pre_validation_stage` at execution time, enforces **all three** gas prices against the actual block prices. Any V3 `AllResources` transaction with a zero or sub-threshold L1 or L1-data gas price passes gateway admission but is deterministically rejected by the blockifier, never producing a receipt or consuming a fee. This allows an unprivileged attacker to flood the mempool with transactions that will never execute.

---

### Finding Description

**Admission side — only L2 gas price is checked:**

`StatelessTransactionValidator::validate_resource_bounds` checks only:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(...)
}
``` [1](#0-0) 

`StatefulTransactionValidator::validate_resource_bounds` fetches the previous block's L2 gas price and calls `validate_tx_l2_gas_price_within_threshold`, which again only inspects `l2_gas.max_price_per_unit`. The `L1Gas` arm is an explicit no-op:

```rust
ValidResourceBounds::L1Gas(_) => {
    // No validation required for legacy transactions.
}
``` [2](#0-1) [3](#0-2) 

The developer-acknowledged gap is recorded in a TODO directly above the function:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(
``` [4](#0-3) 

**Execution side — all three gas prices are enforced:**

`AccountTransaction::check_fee_bounds`, called from `perform_pre_validation_stage`, iterates over all three resources for `AllResources` transactions and rejects any whose `max_price_per_unit` is below the current block price:

```rust
ValidResourceBounds::AllResources(AllResourceBounds {
    l1_gas: l1_gas_resource_bounds,
    l2_gas: l2_gas_resource_bounds,
    l1_data_gas: l1_data_gas_resource_bounds,
}) => {
    let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
        block_info.gas_prices.gas_price_vector(fee_type);
    // ...
    if resource_bounds.max_price_per_unit < actual_gas_price.get() {
        insufficiencies_resource.push(
            ResourceBoundsError::MaxGasPriceTooLow { ... }
        );
    }
``` [5](#0-4) 

The full pre-validation sequence is:

```rust
pub fn perform_pre_validation_stage<S: State + StateReader>(
    &self, state: &mut S, tx_context: &TransactionContext,
) -> TransactionPreValidationResult<()> {
    Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;
    if self.execution_flags.charge_fee {
        self.check_fee_bounds(tx_context)?;          // ← rejects here
        verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
    }
    ...
}
``` [6](#0-5) 

**The temporal gap (analog to the external bug):**

| Stage | What is checked |
|---|---|
| Gateway stateless | `l2_gas.max_price_per_unit >= static min_gas_price` |
| Gateway stateful | `l2_gas.max_price_per_unit >= threshold * prev_block_l2_gas_price` |
| Blockifier `check_fee_bounds` | `l1_gas.max_price_per_unit`, `l1_data_gas.max_price_per_unit`, `l2_gas.max_price_per_unit` all >= current block prices |

A transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` but a valid `l2_gas.max_price_per_unit` clears both gateway layers and enters the mempool. When the batcher pulls it and the blockifier calls `check_fee_bounds`, it is rejected with `InsufficientResourceBounds { MaxGasPriceTooLow { resource: L1Gas } }`. No fee is charged, no receipt is produced, and the nonce state change is rolled back.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can submit an unbounded stream of V3 `AllResources` transactions with `l1_gas.max_price_per_unit = 0` and a valid L2 gas price. Each transaction:
- Passes all gateway checks and enters the mempool
- Consumes a mempool slot, potentially displacing legitimate transactions
- Is pulled by the batcher, consuming CPU for blockifier pre-validation
- Is rejected without fee payment, so the attacker bears no economic cost

Because the mempool has a finite capacity and the attacker pays nothing for rejected transactions, this is a zero-cost mempool-flooding vector.

---

### Likelihood Explanation

The attack requires only a valid Starknet account and the ability to submit RPC transactions. No privileged access, special contract, or chain state is required. The gap is explicitly acknowledged in a TODO comment in production code, confirming it is a known open issue rather than an intentional design choice.

---

### Recommendation

In `StatefulTransactionValidator::validate_resource_bounds`, extend the check to cover all three gas prices for `AllResources` transactions, mirroring the logic already present in `check_fee_bounds`:

```rust
async fn validate_resource_bounds(&self, executable_tx: &ExecutableTransaction)
    -> StatefulTransactionValidatorResult<()>
{
    if self.config.validate_resource_bounds {
        let block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        let prices = &block_info.gas_prices.strk_gas_prices;
        match executable_tx.resource_bounds() {
            ValidResourceBounds::AllResources(bounds) => {
                // existing L2 check
                self.validate_tx_l2_gas_price_within_threshold(
                    executable_tx.resource_bounds(), prices.l2_gas_price)?;
                // new L1 and L1-data checks
                if bounds.l1_gas.max_price_per_unit < prices.l1_gas_price.get() {
                    return Err(...);
                }
                if bounds.l1_data_gas.max_price_per_unit < prices.l1_data_gas_price.get() {
                    return Err(...);
                }
            }
            ValidResourceBounds::L1Gas(bounds) => {
                if bounds.max_price_per_unit < prices.l1_gas_price.get() {
                    return Err(...);
                }
            }
        }
    }
    Ok(())
}
```

The same fix should be applied in `StatelessTransactionValidator::validate_resource_bounds` using the static `min_gas_price` config for L1 and L1-data gas as well.

---

### Proof of Concept

1. Obtain the current network L2 gas price `P_l2` from the previous block header.
2. Submit a V3 Invoke transaction with:
   - `resource_bounds.l2_gas.max_price_per_unit = P_l2` (meets the threshold)
   - `resource_bounds.l1_gas.max_price_per_unit = 0`
   - `resource_bounds.l1_data_gas.max_price_per_unit = 0`
   - `resource_bounds.l2_gas.max_amount` = any non-zero value
3. Observe: the gateway returns a transaction hash (admission succeeds).
4. Observe: the transaction never appears in any block; the batcher rejects it internally with `InsufficientResourceBounds { MaxGasPriceTooLow { resource: L1Gas } }` from `check_fee_bounds`.
5. Repeat in a loop — each iteration costs no fee and occupies a mempool slot.

The blockifier test at `crates/blockifier/src/transaction/transactions_test.rs` lines 1438–1470 already confirms that `l1_gas.max_price_per_unit` one unit below the block price causes `MaxGasPriceTooLow` at execution, proving the execution-side rejection is deterministic. [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L71-76)
```rust
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

**File:** crates/blockifier/src/transaction/transactions_test.rs (L1438-1470)
```rust
    // Max gas price too low, new resource bounds.
    for insufficient_resource in [L1Gas, L2Gas, L1DataGas] {
        let mut invalid_resources = default_resource_bounds;
        match insufficient_resource {
            L1Gas => invalid_resources.l1_gas.max_price_per_unit.0 -= 1,
            L2Gas => invalid_resources.l2_gas.max_price_per_unit.0 -= 1,
            L1DataGas => invalid_resources.l1_data_gas.max_price_per_unit.0 -= 1,
        }

        let invalid_v3_tx = invoke_tx_with_default_flags(InvokeTxArgs {
            resource_bounds: ValidResourceBounds::AllResources(invalid_resources),
            nonce: nonce!(next_nonce),
            ..valid_invoke_tx_args.clone()
        });
        let execution_error = invalid_v3_tx.execute(&mut state, &block_context).unwrap_err();
        assert_matches!(
            execution_error,
            TransactionExecutionError::TransactionPreValidationError(boxed_error)
            => assert_matches!(
                *boxed_error,
                TransactionPreValidationError::TransactionFeeError(boxed_fee_error)
                => assert_matches!(
                    *boxed_fee_error,
                    TransactionFeeError::InsufficientResourceBounds{ errors }
                    => assert_matches!(
                        errors[0],
                        ResourceBoundsError::MaxGasPriceTooLow{resource,..}
                        if resource == insufficient_resource
                    )
                )
            )
        );
    }
```
