### Title
Missing `max_l2_gas_amount` Cap on Declare Transactions Admits Over-Gassed Transactions to Mempool - (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The stateless gateway validator explicitly skips the `max_l2_gas_amount` cap for `Declare` transactions. An attacker with sufficient fee-token balance can submit a `Declare` transaction whose `l2_gas.max_amount` far exceeds the configured per-transaction cap, pass all gateway validation, enter the mempool, and execute with an unbounded initial Sierra gas budget — consuming more block gas per transaction than the protocol intends.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` upper-bound check is guarded by an explicit `Declare` exemption:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

The production default is `max_l2_gas_amount = 1_210_000_000` and `min_gas_price = 8_000_000_000`. [1](#0-0) [2](#0-1) 

Because the stateless check is skipped, a `Declare` transaction with any `l2_gas.max_amount` value (up to `u64::MAX`) passes stateless validation. The only downstream guard is `verify_can_pay_committed_bounds`, which checks that the sender's balance covers `max_possible_fee = l2_gas.max_amount × l2_gas.max_price_per_unit`. That product is computed with **saturating arithmetic**, so astronomically large values saturate to `u128::MAX` and are rejected. However, for values modestly above the cap — e.g., `l2_gas.max_amount = N × max_l2_gas_amount` with a proportionally funded account — the balance check passes and the transaction enters the mempool. [3](#0-2) [4](#0-3) 

Once in the mempool and picked up by the batcher, `TransactionContext::initial_sierra_gas` returns `l2_gas.max_amount` directly for `AllResources` transactions — there is no secondary cap applied before execution begins:

```rust
TransactionInfo::Current(CurrentTransactionInfo {
    resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l2_gas, .. }),
    ..
}) => {
    l2_gas.max_amount   // ← used verbatim as the gas counter
}
``` [5](#0-4) 

The `StatefulValidator` calls `self.execute(tx)` for `Declare` transactions (not the `validate`-only path), so the full execution runs with this inflated gas budget. [6](#0-5) 

### Impact Explanation

A `Declare` transaction admitted with `l2_gas.max_amount = K × max_l2_gas_amount` (K > 1) executes with K times the intended per-transaction gas ceiling. This allows a single transaction to consume a disproportionate share of the block's `sierra_gas` and `proving_gas` budgets, crowding out other transactions. The bouncer enforces block-level totals but does not enforce per-transaction gas limits; the per-transaction limit is supposed to be enforced by the stateless cap that is absent here.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attacker must hold a fee-token balance of at least `l2_gas.max_amount × min_gas_price`. For `l2_gas.max_amount = 2 × max_l2_gas_amount = 2,420,000,000` the required balance is `≈ 1.94 × 10^19` STRK-wei. This is a meaningful economic barrier but not an absolute one for a well-funded actor. The TODO comment in the source confirms the gap is known and unresolved. [7](#0-6) 

### Recommendation

Apply the same `max_l2_gas_amount` check to `Declare` transactions as is already applied to `Invoke` and `DeployAccount`:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Remove the `if let RpcTransaction::Declare(_) = tx { }` guard and the associated TODO. If `Declare` transactions legitimately require a higher gas ceiling (e.g., for large Sierra programs), introduce a separate `max_l2_gas_amount_declare` config field rather than removing the cap entirely.

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = 2_420_000_000` (2× the production cap)
   - `l2_gas.max_price_per_unit = 8_000_000_000` (= `min_gas_price`)
   - A valid Sierra contract class, correct nonce, valid signature
   - Sender account funded with ≥ `2_420_000_000 × 8_000_000_000` fee tokens

2. Submit to the gateway. `StatelessTransactionValidator::validate_resource_bounds` skips the `max_l2_gas_amount` check for `Declare` and returns `Ok(())`.

3. `StatefulTransactionValidator::validate_state_preconditions` calls `validate_resource_bounds` (L2 gas price check only) and `validate_nonce` — both pass.

4. `verify_can_pay_committed_bounds` computes `committed_fee = 2_420_000_000 × 8_000_000_000 = 1.936 × 10^19`; the funded account covers this, so the check passes.

5. The transaction enters the mempool. When the batcher executes it, `initial_sierra_gas = GasAmount(2_420_000_000)` — twice the intended cap — giving the Declare execution twice the normal gas budget. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** crates/apollo_gateway_config/src/config.rs (L188-203)
```rust
impl Default for StatelessTransactionValidatorConfig {
    fn default() -> Self {
        StatelessTransactionValidatorConfig {
            validate_resource_bounds: true,
            min_gas_price: 8_000_000_000,
            max_l2_gas_amount: 1_210_000_000,
            max_calldata_length: 5000,
            max_signature_length: 4000,
            max_contract_bytecode_size: 81920,
            max_contract_class_object_size: 4089446,
            min_sierra_version: VersionId::new(1, 1, 0),
            max_sierra_version: VersionId::new(1, 9, usize::MAX),
            allow_client_side_proving: true,
            max_proof_size: 480000,
        }
    }
```

**File:** crates/starknet_api/src/transaction/fields.rs (L393-413)
```rust
    pub fn max_possible_fee(&self, tip: Tip) -> Fee {
        match self {
            ValidResourceBounds::L1Gas(l1_bounds) => {
                l1_bounds.max_amount.saturating_mul(l1_bounds.max_price_per_unit)
            }
            ValidResourceBounds::AllResources(AllResourceBounds {
                l1_gas,
                l2_gas,
                l1_data_gas,
            }) => l1_gas
                .max_amount
                .saturating_mul(l1_gas.max_price_per_unit)
                .saturating_add(
                    l2_gas
                        .max_amount
                        .saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into())),
                )
                .saturating_add(
                    l1_data_gas.max_amount.saturating_mul(l1_data_gas.max_price_per_unit),
                ),
        }
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-202)
```rust
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = tx_context.max_possible_fee();
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match tx_info {
            TransactionInfo::Current(context) => match &context.resource_bounds {
                L1Gas(l1_gas) => TransactionFeeError::GasBoundsExceedBalance {
                    resource: Resource::L1Gas,
                    max_amount: l1_gas.max_amount,
                    max_price: l1_gas.max_price_per_unit,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
                AllResources(bounds) => TransactionFeeError::ResourcesBoundsExceedBalance {
                    bounds: *bounds,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
            },
            TransactionInfo::Deprecated(context) => TransactionFeeError::MaxFeeExceedsBalance {
                max_fee: context.max_fee,
                balance: balance_to_big_uint(&balance_low, &balance_high),
            },
        })
    }
```

**File:** crates/blockifier/src/context.rs (L55-72)
```rust
    pub fn initial_sierra_gas(&self) -> GasAmount {
        match &self.tx_info {
            TransactionInfo::Deprecated(_)
            | TransactionInfo::Current(CurrentTransactionInfo {
                resource_bounds: ValidResourceBounds::L1Gas(_),
                ..
            }) => self.block_context.versioned_constants.initial_gas_no_user_l2_bound(),
            TransactionInfo::Current(CurrentTransactionInfo {
                resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l2_gas, .. }),
                ..
            }) => {
                #[cfg(feature = "reexecution")]
                if self.block_context.versioned_constants.ignore_user_l2_gas_bound {
                    return self.block_context.versioned_constants.initial_gas_no_user_l2_bound();
                }
                l2_gas.max_amount
            }
        }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
        }
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-243)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
    }

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
