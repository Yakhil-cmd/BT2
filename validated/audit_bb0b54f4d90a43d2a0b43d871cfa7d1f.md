### Title
Gateway Stateful Validator Silently Ignores L1 and L1DataGas Price Bounds, Admitting Transactions That Will Fail at Execution — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` fetches only the previous block's **L2 gas price** and calls `validate_tx_l2_gas_price_within_threshold`, which inspects only `l2_gas.max_price_per_unit`. The `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` fields of an `AllResources` transaction are never compared against the current block prices at the gateway admission layer. This is the direct sequencer analog of the external bug: just as `receiveTokenOrETH()` processes the ERC20 branch while silently ignoring a simultaneously sent `msg.value`, the gateway processes the `AllResources` branch while silently ignoring the L1 and L1DataGas price fields.

---

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` reads only `strk_gas_prices.l2_gas_price` from the previous block and delegates to `validate_tx_l2_gas_price_within_threshold`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 223-243
async fn validate_resource_bounds(...) {
    if self.config.validate_resource_bounds {
        let previous_block_l2_gas_price = self
            .gateway_fixed_block_state_reader
            .get_block_info().await?
            .gas_prices.strk_gas_prices.l2_gas_price;   // ← only L2 price fetched
        self.validate_tx_l2_gas_price_within_threshold(
            executable_tx.resource_bounds(),
            previous_block_l2_gas_price,
        )?;
    }
}
```

Inside `validate_tx_l2_gas_price_within_threshold` (lines 358–390), the `AllResources` arm reads only `l2_gas.max_price_per_unit`; the `l1_gas` and `l1_data_gas` price fields are never touched. The developer-left TODO on line 358 confirms the gap is known but unresolved:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...) {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit; // ← only L2
            // l1_gas.max_price_per_unit and l1_data_gas.max_price_per_unit never checked
            ...
        }
        ValidResourceBounds::L1Gas(_) => { /* No validation required */ }
    }
}
```

The stateless validator (`validate_resource_bounds` in `stateless_transaction_validator.rs`, lines 56–88) has the same gap: it checks only `l2_gas.max_price_per_unit >= min_gas_price` and the aggregate `max_possible_fee > 0`, but never checks `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit` individually.

The blockifier's `check_fee_bounds` (called from `perform_pre_validation_stage`, `account_transaction.rs` lines 374–476) **does** check all three gas prices against the actual block prices. However, `check_fee_bounds` is only reached inside `run_validate_entry_point`, which is **skipped** when `skip_stateful_validations` returns `true`.

`skip_stateful_validations` returns `true` for any invoke transaction with `nonce == 1` and `account_nonce == 0` when a deploy-account transaction for the same sender is already in the mempool — the standard deploy-account + invoke UX flow:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
async fn skip_stateful_validations(...) {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address()).await...
        }
    }
    Ok(false)
}
```

In this path the only resource-bounds check that runs is the L2-gas-only gateway check. A transaction with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` (but a valid `l2_gas.max_price_per_unit`) passes every gateway check and is admitted to the mempool.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

When the batcher later picks up such a transaction and the blockifier runs `check_fee_bounds`, it finds `l1_gas.max_price_per_unit = 0 < actual_l1_gas_price` and raises `ResourceBoundsError::MaxGasPriceTooLow`. The transaction fails at pre-validation; because `charge_fee` is conditioned on `enforce_fee` (which is `true` when any bound is non-zero), the fee transfer is attempted but the transaction reverts with no fee collected from the attacker.

An unprivileged attacker can:
1. Deploy an account (or observe one being deployed).
2. Immediately submit an invoke with `nonce = 1`, valid `l2_gas` price, and `l1_gas.max_price_per_unit = l1_data_gas.max_price_per_unit = 0`.
3. The gateway admits it (skip_validate path).
4. The batcher wastes execution resources and discards the transaction with no fee penalty to the attacker.

This can be repeated at scale to exhaust mempool capacity and batcher throughput.

---

### Likelihood Explanation

**Medium.** The skip_validate path is a documented, intentional UX feature. Any user who knows about the deploy-account + invoke flow can trigger it. The crafted transaction requires only that `l2_gas.max_price_per_unit` meets the threshold while `l1_gas` and `l1_data_gas` prices are set to zero — a trivial construction. No privileged access is required.

---

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or replace it with a new function) to check all three gas prices against their respective previous-block prices, resolving the existing TODO:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_all_gas_prices_within_threshold(
    &self,
    tx_resource_bounds: ValidResourceBounds,
    previous_block_gas_prices: GasPriceVector,  // fetch l1_gas_price and l1_data_gas_price too
) -> StatefulTransactionValidatorResult<()> {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(bounds) => {
            check_price(bounds.l2_gas.max_price_per_unit, previous_block_gas_prices.l2_gas_price)?;
            check_price(bounds.l1_gas.max_price_per_unit, previous_block_gas_prices.l1_gas_price)?;
            check_price(bounds.l1_data_gas.max_price_per_unit, previous_block_gas_prices.l1_data_gas_price)?;
        }
        ValidResourceBounds::L1Gas(_) => {}
    }
    Ok(())
}
```

Additionally, the stateless validator should enforce a non-zero `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` when those amounts are non-zero, mirroring the existing `l2_gas` price floor check.

---

### Proof of Concept

1. Attacker deploys account A; the deploy-account transaction enters the mempool.
2. Attacker submits an invoke transaction from A with:
   - `nonce = 1`, `account_nonce = 0` (triggers skip_validate)
   - `l2_gas = { max_amount: 1_000_000, max_price_per_unit: <threshold> }` (passes L2 check)
   - `l1_gas = { max_amount: 1_000_000, max_price_per_unit: 0 }` (ignored by gateway)
   - `l1_data_gas = { max_amount: 1_000_000, max_price_per_unit: 0 }` (ignored by gateway)
3. `StatelessTransactionValidator::validate_resource_bounds` passes: `max_possible_fee > 0` (l2_gas contributes), `l2_gas.max_price_per_unit >= min_gas_price`.
4. `StatefulTransactionValidator::validate_resource_bounds` passes: only `l2_gas.max_price_per_unit` is checked.
5. `skip_stateful_validations` returns `true` (deploy-account in mempool); `run_validate_entry_point` is skipped entirely.
6. Transaction is admitted to the mempool.
7. Batcher executes: `check_fee_bounds` finds `l1_gas.max_price_per_unit = 0 < actual_l1_gas_price` → `ResourceBoundsError::MaxGasPriceTooLow` → transaction fails, no fee charged. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-461)
```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            let account_address = tx.sender_address();
            debug!("Checking if deploy_account transaction exists for account {account_address}.");
            // We verify that a deploy_account transaction exists for this account. It is sufficient
            // to check if the account exists in the mempool since it means that either it has a
            // deploy_account transaction or transactions with future nonces that passed
            // validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
                .inspect(|exists| {
                    if *exists {
                        debug!("Found deploy_account transaction for account {account_address}.");
                    } else {
                        debug!(
                            "No deploy_account transaction found for account {account_address}."
                        );
                    }
                });
        }
    }

    Ok(false)
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
