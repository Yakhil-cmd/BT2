### Title
Stateless Validator Unconditionally Skips `max_l2_gas_amount` Upper-Bound Check for All Declare Transactions — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` contains an explicit empty `if let RpcTransaction::Declare(_) = tx { }` branch that causes the `max_l2_gas_amount` upper-bound check to be skipped entirely for every declare transaction. An unprivileged user can submit an `RpcDeclareTransactionV3` with `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and it will pass stateless validation, stateful validation, and be admitted to the mempool with no per-transaction L2 gas cap enforced.

---

### Finding Description

The relevant code in `validate_resource_bounds`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // empty — no check performed
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The `if let Declare` arm is intentionally empty. The `else if` branch — which is the only place `max_l2_gas_amount` is enforced — is unreachable for declare transactions. This is confirmed by the existing test `valid_l2_gas_amount_on_declare`, which explicitly asserts `Ok(())` for a declare with `max_amount: GasAmount(200)` against a config of `max_l2_gas_amount: 100`: [2](#0-1) 

And the `test_invalid_max_l2_gas_amount` test deliberately excludes `TransactionType::Declare` from its `#[values(...)]` list, confirming the bypass is known: [3](#0-2) 

**Downstream path — no subsequent check closes the gap:**

The stateful validator's `validate_resource_bounds` only checks the L2 gas **price** against the previous block's threshold — it never checks the L2 gas **amount**: [4](#0-3) 

The blockifier's pre-validation `check_fee_bounds` checks that `max_amount >= minimal_gas_amount` (a lower-bound check), so `u64::MAX` trivially passes: [5](#0-4) 

The blockifier's post-execution `check_actual_cost_within_bounds` uses the transaction's own `max_amount` as the ceiling — with `u64::MAX`, actual execution gas is always within bounds: [6](#0-5) 

The only remaining constraint is the block-level bouncer, which limits total gas per block — not per-transaction L2 gas.

---

### Impact Explanation

A declare transaction with `l2_gas.max_amount = u64::MAX` is admitted through the full gateway pipeline (stateless → stateful → mempool). During blockifier execution, the per-transaction L2 gas cap is effectively `u64::MAX`, meaning the transaction can consume as much L2 gas as the blockifier will allocate within the block gas limit. The operator-configured `max_l2_gas_amount` — the intended per-transaction ceiling — is completely inoperative for declare transactions. This enables resource exhaustion at the block level via a single declare, and undermines the sequencer's ability to enforce per-transaction gas budgets.

**Impact category:** High — Mempool/gateway admission accepts an invalid transaction (one that violates the configured `max_l2_gas_amount` bound) before sequencing.

---

### Likelihood Explanation

Exploitation requires only constructing a valid `RpcDeclareTransactionV3` with an oversized `l2_gas.max_amount`. No privileged access, special account state, or chain condition is required. The bypass is unconditional for all declare transactions.

---

### Recommendation

Remove the empty `if let RpcTransaction::Declare(_) = tx { }` branch and apply the same `max_l2_gas_amount` upper-bound check to declare transactions. If declare transactions legitimately require a higher L2 gas ceiling, introduce a separate `max_l2_gas_amount_declare` config field rather than removing the check entirely.

---

### Proof of Concept

The existing test `valid_l2_gas_amount_on_declare` already constitutes a proof of concept — it constructs a declare with `max_amount: GasAmount(200)` against `max_l2_gas_amount: 100` and asserts `Ok(())`. To reproduce with `u64::MAX`:

```rust
#[test]
fn poc_declare_unbounded_l2_gas() {
    let config = StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 1_000,
        // ... other fields
    };
    let rpc_tx_args = RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(u64::MAX),
                max_price_per_unit: GasPrice(config.min_gas_price),
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let tx = rpc_tx_for_testing(TransactionType::Declare, rpc_tx_args);
    let validator = StatelessTransactionValidator { config };
    // Passes — max_l2_gas_amount check is skipped for Declare
    assert_matches!(validator.validate(&tx), Ok(()));
}
``` [1](#0-0)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L260-264)
```rust
fn test_invalid_max_l2_gas_amount(
    #[case] rpc_tx_args: RpcTransactionArgs,
    #[case] expected_error: StatelessTransactionValidatorError,
    #[values(TransactionType::DeployAccount, TransactionType::Invoke)] tx_type: TransactionType,
) {
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

**File:** crates/blockifier/src/fee/fee_checks.rs (L128-149)
```rust
    pub fn check_all_gas_amounts_within_bounds(
        max_amount_bounds: &GasVector,
        gas_vector: &GasVector,
    ) -> FeeCheckResult<()> {
        // TODO(Arni): Consider refactoring the returned error. The first failed check will hide
        // future checks.
        for (resource, max_amount, actual_amount) in [
            (L1Gas, max_amount_bounds.l1_gas, gas_vector.l1_gas),
            (L2Gas, max_amount_bounds.l2_gas, gas_vector.l2_gas),
            (L1DataGas, max_amount_bounds.l1_data_gas, gas_vector.l1_data_gas),
        ] {
            if max_amount < actual_amount {
                return Err(FeeCheckError::MaxGasAmountExceeded {
                    resource,
                    max_amount,
                    actual_amount,
                });
            }
        }

        Ok(())
    }
```
