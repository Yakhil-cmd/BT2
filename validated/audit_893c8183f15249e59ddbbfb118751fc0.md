### Title
`RpcTransaction::Declare` Bypasses `max_l2_gas_amount` Gateway Admission Check - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The stateless gateway validator enforces a `max_l2_gas_amount` cap on `l2_gas.max_amount` for Invoke and DeployAccount transactions, but explicitly skips this check for Declare transactions. Any unprivileged user can submit a Declare transaction with `l2_gas.max_amount` set to an arbitrarily large value (up to `u64::MAX`), bypassing the configured admission limit and being accepted into the mempool.

### Finding Description

In `validate_resource_bounds`, the check for `max_l2_gas_amount` is guarded by a type-dispatch that silently no-ops for `RpcTransaction::Declare`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // no check performed
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
```

The production configuration sets `max_l2_gas_amount = 1_210_000_000` (1.21 billion gas units). Invoke and DeployAccount transactions exceeding this are rejected at the gateway. Declare transactions are not subject to this check at all.

The test `valid_l2_gas_amount_on_declare` explicitly confirms this behavior is reachable: a Declare transaction with `l2_gas.max_amount = 200` passes when the configured limit is `100`.

The `min_gas_price` check (line 71–76) still applies to Declare transactions, so `l2_gas.max_price_per_unit` must be at least `8_000_000_000` in production. A Declare transaction with `l2_gas.max_amount = u64::MAX` and `max_price_per_unit = 8_000_000_000` would produce a committed fee of `u64::MAX × 8_000_000_000`, which overflows `u64`. Depending on how `max_possible_fee` handles this arithmetic, the downstream `verify_can_pay_committed_bounds` balance check in `perform_pre_validation_stage` could receive a wrapped-around (small) value, potentially allowing the transaction to pass the balance check with a negligible account balance while committing to an astronomically large fee.

### Impact Explanation

This matches **High: Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** A Declare transaction with `l2_gas.max_amount` exceeding `max_l2_gas_amount` is admitted by the gateway when the gateway's own configuration requires it to be rejected. The invariant "no transaction admitted to the mempool may declare an L2 gas amount above `max_l2_gas_amount`" is broken for the Declare transaction type.

### Likelihood Explanation

Any unprivileged user can submit a Declare transaction. No special role, key, or privilege is required. The bypass is unconditional — the code path that skips the check is taken for every Declare transaction regardless of the declared `l2_gas.max_amount`. The TODO comment in the source confirms the developers are aware the check is absent.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to `RpcTransaction::Declare` transactions. Remove the type-dispatch no-op and enforce the limit uniformly:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher gas budget (e.g., for large Sierra programs), introduce a separate `max_l2_gas_amount_declare` configuration parameter rather than removing the check entirely.

### Proof of Concept

1. Construct an `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = GasAmount(u64::MAX)` (or any value > `max_l2_gas_amount`)
   - `l2_gas.max_price_per_unit = GasPrice(min_gas_price)` (satisfies the price floor)
   - A valid Sierra contract class within `max_contract_bytecode_size` and `max_contract_class_object_size`
2. Submit to the gateway's `add_tx` endpoint.
3. Observe that `StatelessTransactionValidator::validate` returns `Ok(())` — the transaction is admitted to the mempool.
4. For comparison, submit an equivalent `RpcInvokeTransactionV3` with the same `l2_gas.max_amount`. Observe that it is rejected with `MaxGasAmountTooHigh`.

The existing test `valid_l2_gas_amount_on_declare` in `stateless_transaction_validator_test.rs` already demonstrates step 3 with `max_amount = 200` against a limit of `100`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L260-271)
```rust
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

**File:** crates/apollo_gateway_config/src/config.rs (L188-204)
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
}
```

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L25-25)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": 1210000000,
```
