### Title
`max_l2_gas_amount` admission check bypassed for `Declare` transactions in `StatelessTransactionValidator::validate_resource_bounds` - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary
The stateless gateway validator enforces a `max_l2_gas_amount` cap on `Invoke` and `DeployAccount` transactions but explicitly skips this check for `Declare` transactions. An attacker with sufficient STRK balance can submit a `Declare` transaction with `l2_gas.max_amount` arbitrarily exceeding the configured limit, bypassing the intended admission control and getting the transaction accepted into the mempool.

### Finding Description
In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` check is guarded by a type branch that silently no-ops for `Declare`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The default `max_l2_gas_amount` is `1_210_000_000`. [2](#0-1) 

The test suite explicitly documents and asserts this asymmetry: `test_invalid_max_l2_gas_amount` only covers `TransactionType::DeployAccount` and `TransactionType::Invoke`, and a separate test `valid_l2_gas_amount_on_declare` asserts that a `Declare` with `max_amount = 200` passes when the limit is `100`. [3](#0-2) [4](#0-3) 

No downstream check in the stateful path closes this gap. The stateful `validate_resource_bounds` only checks `l2_gas.max_price_per_unit` against the previous block price — it does not check `max_amount` at all. [5](#0-4) 

The blockifier's `check_fee_bounds` in `perform_pre_validation_stage` only checks that `max_amount >= minimal_gas_amount` (a lower-bound check), never an upper-bound check. [6](#0-5) 

`verify_can_pay_committed_bounds` checks that the account balance covers `max_amount * max_price_per_unit`. This is a balance check, not a gas-amount cap. An attacker with sufficient balance passes it regardless of how large `max_amount` is. [7](#0-6) 

Furthermore, `StatefulValidator::perform_validations` routes `Declare` transactions through full `execute()` rather than the lighter `perform_pre_validation_stage` + `validate` path used for `Invoke`, so no additional upper-bound check is applied there either. [8](#0-7) 

### Impact Explanation
A `Declare` transaction with `l2_gas.max_amount` far exceeding `max_l2_gas_amount` is admitted through the gateway and into the mempool when it should be rejected. This directly matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."** The `max_l2_gas_amount` limit exists precisely to prevent oversized gas claims from entering the mempool; the Declare path is a complete bypass of that control.

### Likelihood Explanation
Any account holder with sufficient STRK balance (to satisfy `verify_can_pay_committed_bounds`) can trigger this with a single well-formed `Declare` transaction. No privileged access, no special network position, and no race condition is required. The bypass is unconditional for all `Declare` transactions.

### Recommendation
Apply the same `max_l2_gas_amount` upper-bound check to `Declare` transactions in `validate_resource_bounds`. Remove the `if let RpcTransaction::Declare(_) = tx { }` branch and apply the check uniformly:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

The TODO comment `// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.` should be resolved as a fix, not left as a known gap. [1](#0-0) 

### Proof of Concept
1. Configure a node with default settings: `max_l2_gas_amount = 1_210_000_000`, `min_gas_price = 8_000_000_000`.
2. Fund an account with at least `1_210_000_001 * 8_000_000_000 ≈ 9.68 × 10^18` STRK (or any amount covering `max_amount * max_price_per_unit`).
3. Construct a valid `RpcDeclareTransaction::V3` with:
   - `l2_gas.max_amount = 1_210_000_001` (one above the limit)
   - `l2_gas.max_price_per_unit = 8_000_000_000` (at the minimum)
   - A valid Sierra class, valid signature, nonce, etc.
4. Submit to the gateway.
5. **Stateless validator**: the `max_l2_gas_amount` check is skipped for `Declare` → passes.
6. **Stateful validator**: `validate_resource_bounds` only checks price, not amount → passes. `verify_can_pay_committed_bounds` checks balance → passes (account is funded).
7. Transaction is admitted to the mempool with `l2_gas.max_amount` exceeding the configured limit, violating the admission invariant.

An equivalent `Invoke` or `DeployAccount` transaction with the same `l2_gas.max_amount` would be rejected at step 5 with `MaxGasAmountTooHigh`.

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L243-271)
```rust
#[rstest]
#[case::max_l2_gas_amount_too_high(
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount + 1),
                max_price_per_unit: GasPrice(DEFAULT_VALIDATOR_CONFIG.min_gas_price),
            },
            ..Default::default()
        },
        ..Default::default()
    },
    StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: GasAmount(DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount + 1),
        max_gas_amount: DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount
    },
)]
fn test_invalid_max_l2_gas_amount(
    #[case] rpc_tx_args: RpcTransactionArgs,
    #[case] expected_error: StatelessTransactionValidatorError,
    #[values(TransactionType::DeployAccount, TransactionType::Invoke)] tx_type: TransactionType,
) {
    let tx_validator =
        StatelessTransactionValidator { config: DEFAULT_VALIDATOR_CONFIG.to_owned() };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_eq!(tx_validator.validate(&tx).unwrap_err(), expected_error);
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L427-458)
```rust
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
