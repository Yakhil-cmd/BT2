The code is clear and I have everything needed to assess this.

The code is fully readable. Here is the complete analysis.

---

### Title
Declare Transactions Unconditionally Bypass `max_l2_gas_amount` Gateway Admission Check — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` contains an intentional but unguarded exemption that skips the `max_l2_gas_amount` upper-bound check for every `RpcTransaction::Declare` variant. Any unprivileged user can submit a Declare transaction with `l2_gas.max_amount = u64::MAX` and the stateless gateway will admit it, violating the stated admission invariant. The bypass is confirmed by both the production code and an existing test that asserts `Ok(())` for an out-of-limit Declare.

### Finding Description

In `validate_resource_bounds`, the check that enforces `max_l2_gas_amount` is structured as:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // empty — no check performed
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The `if let RpcTransaction::Declare(_) = tx { }` arm is an **empty block**. Rust evaluates it as the true branch, so the `else if` (the actual bound check) is never reached for Declare transactions. The TODO comment acknowledges the gap explicitly.

The existing test `valid_l2_gas_amount_on_declare` codifies this as expected behavior: a Declare transaction with `max_amount: GasAmount(200)` against a config of `max_l2_gas_amount: 100` asserts `Ok(())`. [2](#0-1) 

### Impact Explanation

**Concrete admission bypass (High):** The gateway's `max_l2_gas_amount` invariant — which exists to bound the L2 gas a single transaction may claim — is not enforced for Declare transactions. Any unprivileged caller can submit a Declare with `l2_gas.max_amount = u64::MAX` and receive `Ok(())` from the stateless validator.

**Downstream propagation analysis:**

- `max_possible_fee()` uses saturating arithmetic throughout, so `u64::MAX × price` saturates to `Fee(u128::MAX)` without panicking. [3](#0-2) 

- `verify_can_pay_committed_bounds` then checks whether the account balance covers `Fee(u128::MAX)`. For any realistic account balance this fails, and the transaction is rejected at the stateful validation stage. [4](#0-3) 

- If `min_gas_price = 0` (making `max_price_per_unit = 0` permissible), the l2_gas fee contribution is zero, `max_possible_fee()` reflects only l1/l1_data_gas bounds, and the transaction can pass `verify_can_pay_committed_bounds`. In that path, `initial_sierra_gas()` returns `GasAmount(u64::MAX)` directly from the user-supplied bound. [5](#0-4) 

- `max_steps` computation saturating-divides `u64::MAX` by `l2_gas_per_step` and then takes `min(result, block_upper_bound)`, so the block-level cap prevents unbounded execution. [6](#0-5) 

The concrete corrupted value is the **admission decision itself**: the gateway accepts a Declare transaction that the `max_l2_gas_amount` config is explicitly designed to reject. Downstream checks (stateful balance check, block gas cap) provide partial mitigation but do not restore the invariant at the gateway layer.

### Likelihood Explanation

Trivially exploitable by any user who can submit an RPC transaction. No privileges, keys, or special state are required. The bypass is unconditional for all Declare transactions regardless of the configured `max_l2_gas_amount`.

### Recommendation

Remove the empty `if let RpcTransaction::Declare(_) = tx { }` arm and apply the same `max_l2_gas_amount` check uniformly, or introduce a separate `max_l2_gas_amount_declare` config field if Declare transactions legitimately require a different (higher) bound. The TODO comment should be resolved rather than left as a silent bypass.

```rust
// Apply to all transaction types uniformly:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

### Proof of Concept

The existing test already proves the bypass:

```rust
// From stateless_transaction_validator_test.rs lines 173-201:
// Config: max_l2_gas_amount = 100
// Tx:     l2_gas.max_amount = GasAmount(200)  (2× the limit)
// Type:   Declare
// Result: Ok(())   ← admission invariant violated
fn valid_l2_gas_amount_on_declare(…) {
    assert_matches!(tx_validator.validate(&tx), Ok(()));
}
``` [7](#0-6) 

A unit test with `l2_gas.max_amount = GasAmount(u64::MAX)` against any `max_l2_gas_amount > 0` config would produce the same `Ok(())` result for Declare, while the identical bounds on an Invoke or DeployAccount transaction would return `Err(MaxGasAmountTooHigh)`. [8](#0-7)

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

**File:** crates/blockifier/src/context.rs (L62-71)
```rust
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
```

**File:** crates/blockifier/src/execution/entry_point.rs (L451-470)
```rust
                ValidResourceBounds::AllResources(AllResourceBounds {
                    l2_gas: ResourceBounds { max_amount, .. },
                    ..
                }) => {
                    if l2_gas_per_step.is_zero() {
                        u64::MAX
                    } else {
                        max_amount.0.saturating_div(l2_gas_per_step)
                    }
                }
            },
        };

        // Use saturating upper bound to avoid overflow. This is safe because the upper bound is
        // bounded above by the block's limit, which is a usize.
        let tx_upper_bound = usize_from_u64(tx_upper_bound_u64).unwrap_or_else(|_| {
            log::warn!("Failed to convert u64 to usize: {tx_upper_bound_u64}.");
            usize::MAX
        });
        min(tx_upper_bound, block_upper_bound)
```
