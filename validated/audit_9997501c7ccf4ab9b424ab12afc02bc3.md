### Title
`max_l2_gas_amount` Admission Limit Not Enforced for Declare Transactions — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The gateway stateless validator enforces a `max_l2_gas_amount` cap on `l2_gas.max_amount` for Invoke and DeployAccount transactions, but explicitly skips this check for Declare transactions. Any unprivileged user can submit a Declare transaction with an arbitrarily large `l2_gas.max_amount` (up to `u64::MAX`) and it will be admitted through the gateway, bypassing the admission limit that exists to protect the sequencer.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the check for `l2_gas.max_amount` against `config.max_l2_gas_amount` is guarded by an explicit early-return for Declare transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
```

The production config sets `max_l2_gas_amount = 1_210_000_000`. For Invoke and DeployAccount transactions, any `l2_gas.max_amount` exceeding this value is rejected at the gateway. For Declare transactions, no upper bound is applied — the field is accepted at any value.

This is confirmed by the test `valid_l2_gas_amount_on_declare`, which explicitly asserts that a Declare transaction with `l2_gas.max_amount = 200` passes when the configured limit is `100`. [1](#0-0) [2](#0-1) 

The production limit value is: [3](#0-2) 

### Impact Explanation

An attacker can submit a Declare transaction with `l2_gas.max_amount = u64::MAX` (or any value above `1_210_000_000`). This transaction passes the gateway stateless validator and enters the mempool. Downstream, `max_steps` in `EntryPointExecutionContext::max_steps` is derived from `l2_gas.max_amount` for `AllResources` transactions, giving the transaction an enormous step budget before it is capped by the block-level `block_upper_bound`. The `verify_can_pay_committed_bounds` check at the blockifier level computes committed fee as `max_amount * max_price_per_unit`; if `max_price_per_unit` is set to a small non-zero value such that the product fits within the account balance, the transaction proceeds through full blockifier validation and execution.

The broken invariant is: *all transactions admitted through the gateway must satisfy `l2_gas.max_amount <= max_l2_gas_amount`*. This invariant holds for Invoke and DeployAccount but not for Declare. [4](#0-3) 

### Likelihood Explanation

The trigger requires only a standard Declare transaction with an oversized `l2_gas.max_amount` field. No privileged access, special account, or unusual network condition is required. The bypass is stateless and reproducible on every gateway instance. The TODO comment in the source code confirms the gap is known but unresolved.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to Declare transactions. Remove the empty `if let RpcTransaction::Declare(_) = tx {}` branch and apply the check unconditionally:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Update the test `valid_l2_gas_amount_on_declare` to expect rejection, and add a corresponding passing test with a Declare transaction whose `l2_gas.max_amount` is within the limit.

### Proof of Concept

1. Construct an `RpcDeclareTransactionV3` with `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and any non-zero `max_price_per_unit`.
2. Submit it to the gateway's `add_tx` endpoint.
3. Observe that `StatelessTransactionValidator::validate` returns `Ok(())` — the transaction is admitted.
4. Submit an equivalent `RpcInvokeTransactionV3` with the same `l2_gas.max_amount`.
5. Observe that it is rejected with `StatelessTransactionValidatorError::MaxGasAmountTooHigh`.

The asymmetry is directly demonstrated by the existing test: [5](#0-4) 

which tests only `DeployAccount` and `Invoke` transaction types for the `MaxGasAmountTooHigh` error, with no corresponding test for `Declare`.

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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
```

**File:** crates/blockifier/src/execution/entry_point.rs (L451-460)
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
```
