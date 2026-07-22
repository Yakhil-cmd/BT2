### Title
Declare Transactions Bypass `max_l2_gas_amount` Stateless Check, Causing Valid Declares to Be Rejected at Stateful Validation via Uncapped `max_possible_fee()` — (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` intentionally skips the `max_l2_gas_amount` upper-bound check for Declare transactions (with an explicit `TODO` comment). This allows a Declare transaction to carry an arbitrarily large `l2_gas.max_amount`. Downstream, `max_possible_fee()` multiplies that raw, uncapped value by `max_price_per_unit` to compute the committed fee used in `verify_can_pay_committed_bounds`. Because the execution engine independently caps actual gas consumption at `execute_max_sierra_gas`, the committed-fee check uses a value that can be orders of magnitude larger than the fee that would ever actually be charged, causing the transaction to be rejected even when the account holds sufficient balance to cover the real cost.

---

### Finding Description

**Stateless validator skips the `max_l2_gas_amount` guard for Declare:** [1](#0-0) 

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
```

The production default for `max_l2_gas_amount` is `1_210_000_000`. [2](#0-1) 

A Declare transaction with `l2_gas.max_amount = u64::MAX` (or any value above `1_210_000_000`) passes this check without error.

**`max_possible_fee()` uses the raw, uncapped `l2_gas.max_amount`:** [3](#0-2) 

```rust
ValidResourceBounds::AllResources(AllResourceBounds { l1_gas, l2_gas, l1_data_gas }) =>
    l1_gas.max_amount.saturating_mul(l1_gas.max_price_per_unit)
    .saturating_add(
        l2_gas.max_amount.saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into())),
    )
    ...
```

For `l2_gas.max_amount = u64::MAX` and `l2_gas.max_price_per_unit = 8_000_000_000` (the minimum accepted by the stateless validator), this saturates to `u128::MAX`.

**`verify_can_pay_committed_bounds` uses `max_possible_fee()` as the committed amount:** [4](#0-3) 

```rust
let committed_fee = tx_context.max_possible_fee();
let (balance_low, balance_high, can_pay) =
    get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
```

**The execution engine independently caps gas at `execute_max_sierra_gas`:** [5](#0-4) 

The actual gas consumed by a Declare transaction is bounded by `execute_max_sierra_gas = 1_100_000_000` (v0.14.2). The balance check, however, uses the raw `l2_gas.max_amount` from the transaction, not the capped value.

**Stateful validation for Declare runs full execution including `perform_pre_validation_stage`:** [6](#0-5) 

```rust
ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
```

`execute` calls `perform_pre_validation_stage`, which calls `verify_can_pay_committed_bounds` when `charge_fee` is true. [7](#0-6) 

**The test `valid_l2_gas_amount_on_declare` confirms the skip is intentional and tested:** [8](#0-7) 

A Declare with `l2_gas.max_amount = 200` (above the configured limit of `100`) is explicitly expected to pass stateless validation.

---

### Impact Explanation

This is a **High** impact issue matching: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

A user submitting a Declare transaction with `l2_gas.max_amount` set to any value above `execute_max_sierra_gas` (e.g., `2_000_000_000`) will have their transaction rejected at stateful validation with an "insufficient balance" error, even if their account holds enough STRK to pay for the actual gas consumed (at most `execute_max_sierra_gas × max_price_per_unit`). The transaction is structurally valid and would succeed if `l2_gas.max_amount` were set to a value ≤ `execute_max_sierra_gas`.

The broken invariant is: *the committed-fee balance check should be bounded by the maximum fee that can actually be charged, not by the user's stated upper bound when that upper bound exceeds the protocol's execution gas cap.*

This is the direct analog to the external bug: `_incomingTokenBalance()` returned the raw allowance (potentially `type(uint256).max`) instead of `min(allowance, balance)`, causing `transferFrom()` to fail. Here, `max_possible_fee()` uses the raw `l2_gas.max_amount` instead of `min(l2_gas.max_amount, execute_max_sierra_gas) × max_price_per_unit`, causing `verify_can_pay_committed_bounds` to fail.

---

### Likelihood Explanation

Any unprivileged user can submit a Declare transaction with an arbitrarily large `l2_gas.max_amount`. The stateless validator explicitly skips the check. The stateful validator then performs expensive blockifier execution before rejecting the transaction. This is reachable from the public RPC endpoint with no special privileges.

---

### Recommendation

Remove the special-case skip for Declare transactions in `validate_resource_bounds`:

```rust
// Remove the Declare exception:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Alternatively, cap `l2_gas.max_amount` by `execute_max_sierra_gas` inside `max_possible_fee()` so the committed-fee check reflects the maximum fee that can actually be charged:

```rust
// Analog to the external fix: min(allowance, balance)
let effective_l2_amount = l2_gas.max_amount.min(execute_max_sierra_gas);
effective_l2_amount.saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into()))
```

---

### Proof of Concept

1. Construct a valid Declare transaction with:
   - `l2_gas.max_amount = 2_000_000_000` (above `max_l2_gas_amount = 1_210_000_000`)
   - `l2_gas.max_price_per_unit = 8_000_000_000` (the minimum accepted)
   - Account balance = `8_800_000_000_000_000_000` (enough to pay `execute_max_sierra_gas × price`)

2. Submit to the gateway. `StatelessTransactionValidator::validate_resource_bounds` accepts it because the `max_l2_gas_amount` check is skipped for Declare.

3. Stateful validation runs. `max_possible_fee()` computes `2_000_000_000 × 8_000_000_000 = 1.6 × 10^19`.

4. `verify_can_pay_committed_bounds` checks if the account can pay `1.6 × 10^19` STRK. The account only holds `8.8 × 10^18` STRK.

5. The transaction is rejected with `GasBoundsExceedBalance` / `ResourcesBoundsExceedBalance`, even though the actual gas consumed would be at most `execute_max_sierra_gas = 1_100_000_000` units, costing at most `8.8 × 10^18` STRK — exactly what the account holds.

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L78-85)
```rust
        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
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

**File:** crates/starknet_api/src/transaction/fields.rs (L398-413)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L173-201)
```rust
#[rstest]
#[case::l2_gas_amount_out_of_limit(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 100,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(200),
                ..NON_EMPTY_RESOURCE_BOUNDS
            },
            ..Default::default()
        },
        ..Default::default()
    }
)]
fn valid_l2_gas_amount_on_declare(
    #[case] config: StatelessTransactionValidatorConfig,
    #[case] rpc_tx_args: RpcTransactionArgs,
) {
    let tx_type = TransactionType::Declare;
    let tx_validator = StatelessTransactionValidator { config };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_matches!(tx_validator.validate(&tx), Ok(()));
}
```
