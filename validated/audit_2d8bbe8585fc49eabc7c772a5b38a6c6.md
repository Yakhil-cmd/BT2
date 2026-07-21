### Title
Missing `max_l2_gas_amount` Upper-Bound Validation for Declare Transactions Allows Gateway Admission of Oversized Resource Bounds — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. Every other transaction type (Invoke, DeployAccount) is rejected at the gateway if `l2_gas.max_amount` exceeds `config.max_l2_gas_amount` (default 1,210,000,000). A Declare transaction with an arbitrarily large `l2_gas.max_amount` passes all gateway checks and is admitted to the mempool, violating the invariant the limit is meant to enforce.

---

### Finding Description

In `validate_resource_bounds`, the upper-bound check is guarded by an empty `if let` branch that silently skips the check for Declare:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← no check; falls through
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The production default is `max_l2_gas_amount = 1_210_000_000`: [2](#0-1) 

The gap is confirmed by a dedicated test that asserts a Declare with `max_amount = 200` passes even when the configured limit is `100`: [3](#0-2) 

The stateful validator (`extract_state_nonce_and_run_validations`) only checks the L2 gas *price* against the previous block, not the *amount*: [4](#0-3) 

The blockifier's `check_fee_bounds` only enforces a *lower* bound (`minimal_gas_amount ≤ max_amount`), never an upper bound: [5](#0-4) 

`verify_can_pay_committed_bounds` checks `balance ≥ max_amount × max_price_per_unit`, which is the only downstream guard. With `min_gas_price = 8_000_000_000` Fri/gas, an attacker holding ~970 STRK can set `max_amount = 121_000_000_000` (100× the enforced limit) and pass every check. [6](#0-5) 

---

### Impact Explanation

The gateway's own admission invariant — "no transaction may claim more than `max_l2_gas_amount` L2 gas" — is broken for Declare transactions. A funded attacker can submit a Declare with `l2_gas.max_amount` far exceeding the limit that applies to every other transaction type. This maps to:

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

Concretely, the oversized gas bound is propagated into the blockifier's `initial_sierra_gas()` computation, giving the Declare execution a gas budget that no Invoke or DeployAccount transaction can obtain. If the batcher's bouncer accounts for `max_amount` when reserving block capacity, a single such Declare can crowd out all other transactions in a block.

---

### Likelihood Explanation

The trigger is unprivileged: any account holding a few hundred STRK can craft the transaction. The TODO comment in the source confirms the developers are aware the check is absent. The test `valid_l2_gas_amount_on_declare` explicitly documents the bypass as currently accepted behavior.

---

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to Declare transactions, or introduce a separate `max_l2_gas_amount_declare` configuration value. Remove the empty `if let RpcTransaction::Declare(_) = tx {}` branch and resolve the TODO.

---

### Proof of Concept

1. Craft a `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = 121_000_000_000` (100× the enforced limit of 1,210,000,000)
   - `l2_gas.max_price_per_unit = 8_000_000_000` (minimum allowed price)
   - Sender account balance ≥ `121_000_000_000 × 8_000_000_000 = 968 × 10^18` Fri ≈ 968 STRK
2. Submit via `add_tx`.
3. `StatelessTransactionValidator::validate` reaches the `if let RpcTransaction::Declare(_) = tx {}` branch and skips the `MaxGasAmountTooHigh` check — the transaction passes stateless validation.
4. `StatefulTransactionValidator` checks only the L2 gas *price* and the nonce — both pass.
5. `verify_can_pay_committed_bounds` confirms the account balance covers the committed fee — passes.
6. The transaction is admitted to the mempool with `l2_gas.max_amount = 121_000_000_000`, a value that would be unconditionally rejected for any Invoke or DeployAccount transaction.

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

**File:** crates/apollo_gateway_config/src/config.rs (L193-194)
```rust
            max_l2_gas_amount: 1_210_000_000,
            max_calldata_length: 5000,
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-476)
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
            }
            TransactionInfo::Deprecated(context) => {
                let max_fee = context.max_fee;
                let min_fee = get_fee_by_gas_vector(
                    block_info,
                    minimal_gas_amount_vector,
                    fee_type,
                    tx_context.effective_tip(),
                );
                if max_fee < min_fee {
                    return Err(TransactionPreValidationError::TransactionFeeError(Box::new(
                        TransactionFeeError::MaxFeeTooLow { min_fee, max_fee },
                    )));
                }
            }
        };
        Ok(())
    }
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-203)
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
}
```
