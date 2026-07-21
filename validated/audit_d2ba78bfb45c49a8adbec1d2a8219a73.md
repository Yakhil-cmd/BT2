### Title
`Declare` Transactions Bypass `max_l2_gas_amount` Gateway Admission Check — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The `StatelessTransactionValidator` enforces an upper-bound check on `l2_gas.max_amount` for `Invoke` and `DeployAccount` transactions but explicitly skips this check for `Declare` transactions. An attacker can submit a `Declare` transaction with an arbitrarily large `l2_gas.max_amount` (up to `u64::MAX`) and have it admitted through the gateway and into the mempool, bypassing the admission control that exists for all other transaction types.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` upper-bound check is guarded by a type-specific branch that silently skips `Declare` transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The default `max_l2_gas_amount` is `1_210_000_000`. [2](#0-1) 

For `Invoke` and `DeployAccount`, a transaction with `l2_gas.max_amount > max_l2_gas_amount` is rejected at the gateway stateless path. The test `test_invalid_max_l2_gas_amount` explicitly covers only `TransactionType::DeployAccount` and `TransactionType::Invoke`, confirming `Declare` is excluded: [3](#0-2) 

The companion test `valid_l2_gas_amount_on_declare` explicitly asserts that a `Declare` with `max_amount: GasAmount(200)` passes when `max_l2_gas_amount: 100`, confirming the bypass is intentional in the current code: [4](#0-3) 

No downstream guard in the stateful path or blockifier enforces an upper bound on `max_amount`. `check_fee_bounds` in `perform_pre_validation_stage` only checks that `max_amount >= minimal_gas_amount` (a lower bound), never an upper bound: [5](#0-4) 

`verify_can_pay_committed_bounds` checks balance against `max_amount * max_price_per_unit`. With `max_amount = u64::MAX` and any non-zero `max_price_per_unit`, this multiplication overflows, potentially corrupting the balance comparison and allowing the transaction to pass the balance check incorrectly.

### Impact Explanation

A `Declare` transaction with `l2_gas.max_amount = u64::MAX` passes the gateway stateless validator and enters the mempool. This:

1. Violates the gateway's own admission invariant — the same field is bounded for `Invoke` and `DeployAccount` but not for `Declare`.
2. Allows mempool pollution with transactions that carry an out-of-range gas bound.
3. Risks arithmetic overflow in `verify_can_pay_committed_bounds` when computing `max_amount * max_price_per_unit`, potentially producing a wrong balance-sufficiency result.

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The trigger is fully unprivileged: any user can submit an `RpcDeclareTransaction::V3` with an arbitrary `resource_bounds.l2_gas.max_amount`. The gateway's `declare_compilation_semaphore` limits concurrent compilations but does not prevent the admission of a single malformed transaction. The TODO comment in the source confirms the gap is known but unresolved.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to `Declare` transactions, removing the type-specific exemption:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If `Declare` transactions legitimately require a higher gas ceiling, introduce a separate `max_l2_gas_amount_declare` config parameter rather than removing the check entirely.

### Proof of Concept

1. Construct an `RpcDeclareTransaction::V3` with:
   - `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)`
   - `resource_bounds.l2_gas.max_price_per_unit = GasPrice(min_gas_price)` (to pass the price floor check)
   - All other fields valid.
2. Submit to the gateway via `POST /add_transaction`.
3. Observe: the stateless validator returns `Ok(())` — the `MaxGasAmountTooHigh` error is never raised for `Declare`.
4. The transaction proceeds to stateful validation and mempool admission.
5. For `Invoke` or `DeployAccount` with identical `max_amount`, the gateway returns `MaxGasAmountTooHigh` at step 3, confirming the inconsistency. [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L45-53)
```rust
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-385)
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
```
