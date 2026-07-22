### Title
Declare Transactions Bypass `max_l2_gas_amount` Gateway Admission Check — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The stateless gateway validator enforces a `max_l2_gas_amount` ceiling on the declared L2 gas amount for Invoke and DeployAccount transactions, but an explicit type-branch exempts Declare transactions from this check entirely. Any user can submit a Declare transaction with an arbitrarily large `l2_gas.max_amount` and it will be admitted to the mempool, violating the gateway's own admission policy.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` guard is written as:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The empty `if`-branch for `Declare` causes the `else if` to be skipped unconditionally. The existing test `valid_l2_gas_amount_on_declare` explicitly confirms this: a Declare transaction with `l2_gas.max_amount = 200` passes validation even when `max_l2_gas_amount = 100`. [2](#0-1) 

The stateful validator's `validate_resource_bounds` only checks the L2 gas *price* against the previous block price, not the gas *amount*: [3](#0-2) 

The blockifier's `check_fee_bounds` only rejects transactions whose declared `max_amount` is *too low* to cover the actual cost — it never rejects a transaction for declaring an amount that is *too high*: [4](#0-3) 

No downstream check compensates for the missing gateway-level ceiling on Declare's `l2_gas.max_amount`.

**Analog to the external report:** The external bug has WstETH requiring a two-step conversion that is bypassed when a PToken wraps it, because the identity check `if (asset == wsteth)` does not fire for the wrapper address. Here, the identity check `if let RpcTransaction::Declare(_) = tx { }` fires for Declare but executes an empty body, causing the `max_l2_gas_amount` guard to be skipped — the same structural bypass pattern.

### Impact Explanation

A Declare transaction with `l2_gas.max_amount` set to any value (e.g., `u64::MAX`) passes all gateway validation stages and is admitted to the mempool. This violates the configured admission policy that is correctly enforced for Invoke and DeployAccount transactions. The `max_l2_gas_amount` limit exists to bound the maximum possible fee a transaction can commit to; bypassing it for Declare allows a transaction to commit to an arbitrarily large fee ceiling, which:

- Causes `verify_can_pay_committed_bounds` to require the account to hold a correspondingly large balance, potentially locking funds or causing unexpected pre-validation failures at the blockifier stage rather than at the gateway.
- Admits transactions that should be rejected at the gateway, matching the "Mempool/gateway/RPC admission accepts invalid transactions" impact category.

### Likelihood Explanation

Any unprivileged user can submit a Declare transaction via the public RPC endpoint. No special account state is required to trigger the bypass — only setting `l2_gas.max_amount` above the configured limit suffices. The TODO comment in the source confirms the developers are aware the check is absent.

### Recommendation

Remove the Declare exemption and apply the same `max_l2_gas_amount` ceiling to all transaction types:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher ceiling (e.g., because compilation is more expensive), introduce a separate `max_l2_gas_amount_declare` configuration parameter rather than removing the check entirely.

### Proof of Concept

1. Configure the gateway with `max_l2_gas_amount = 100` and `validate_resource_bounds = true`.
2. Submit a Declare V3 transaction with `l2_gas.max_amount = 1_000_000_000` and a valid `l2_gas.max_price_per_unit` above `min_gas_price`.
3. Observe that `StatelessTransactionValidator::validate` returns `Ok(())` — the `MaxGasAmountTooHigh` error is never raised.
4. Submit an equivalent Invoke transaction with the same `l2_gas.max_amount = 1_000_000_000`.
5. Observe that the Invoke transaction is rejected with `MaxGasAmountTooHigh`.

The existing test `valid_l2_gas_amount_on_declare` already encodes step 3 as an expected-pass case, confirming the bypass is present in the production code path. [5](#0-4)

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
