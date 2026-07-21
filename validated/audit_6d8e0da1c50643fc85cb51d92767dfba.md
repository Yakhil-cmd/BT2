### Title
Declare Transactions Bypass `max_l2_gas_amount` Gateway Admission Check — (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `l2_gas.max_amount` upper-bound check for `Declare` transactions. Any unprivileged user can submit a `Declare` transaction with `l2_gas.max_amount` set to an arbitrarily large value (up to `u64::MAX`) and it will pass all stateless gateway checks, violating the admission invariant that `max_l2_gas_amount` is meant to enforce for every transaction type.

### Finding Description

In `validate_resource_bounds`, the check that rejects transactions whose `l2_gas.max_amount` exceeds the configured `max_l2_gas_amount` ceiling is guarded by an explicit type-branch that silently skips `Declare` transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The test `valid_l2_gas_amount_on_declare` explicitly confirms this is the current behavior: a `Declare` with `max_amount = 200` passes when `max_l2_gas_amount = 100`. [2](#0-1) 

The same check correctly rejects `Invoke` and `DeployAccount` transactions: [3](#0-2) 

The full `validate` call-chain for a `Declare` transaction is:

1. `validate_contract_address` ✓
2. `validate_empty_account_deployment_data` ✓
3. `validate_empty_paymaster_data` ✓
4. `validate_resource_bounds` — **skips `max_l2_gas_amount` for Declare** ✗
5. `validate_tx_size` — **also skips calldata-length check for Declare** (returns `Ok(())` immediately)
6. `validate_nonce_data_availability_mode` ✓
7. `validate_fee_data_availability_mode` ✓
8. `validate_declare_tx` (Sierra version, class length, entry-point uniqueness) ✓ [4](#0-3) [5](#0-4) 

### Impact Explanation

The `max_l2_gas_amount` ceiling exists to prevent any single transaction from claiming more L2 gas than the block can accommodate, protecting the mempool and batcher from transactions that would be structurally incompatible with block limits. By exempting `Declare` transactions from this check, the gateway admits transactions that violate this invariant.

A downstream partial guard exists: `verify_can_pay_committed_bounds` (called from `perform_pre_validation_stage`) checks that the account balance covers `max_amount × max_price_per_unit`. [6](#0-5) 

However, this guard is bypassed when `l2_gas.max_price_per_unit` is set to zero (or the minimum allowed value) while `l1_gas.max_price_per_unit` is set just above `min_gas_price` to satisfy the non-zero fee check. In that configuration the L2 gas contribution to `max_possible_fee` is zero, so the balance check passes regardless of `l2_gas.max_amount`. The transaction is then admitted to the mempool with a declared L2 gas ceiling of `u64::MAX`, which is `~3.7 × 10^9` times the block's `receipt_l2_gas` limit of `5,800,000,000`. [7](#0-6) 

### Likelihood Explanation

The trigger is fully unprivileged: any account that can submit a `Declare` transaction (subject only to the `is_authorized_declarer` allowlist, which may be open) can craft this payload. The exploit path requires only setting `l2_gas.max_amount` to an oversized value, which is a single field in the RPC transaction struct. The TODO comment in the source confirms the developers are aware the check is absent.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to `Declare` transactions as is already applied to `Invoke` and `DeployAccount`:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Remove the `if let RpcTransaction::Declare(_) = tx { }` branch entirely, or configure a separate (potentially higher) `max_l2_gas_amount_declare` limit if `Declare` transactions legitimately require more L2 gas headroom than `Invoke` transactions.

### Proof of Concept

1. Construct an `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = u64::MAX` (or any value > `max_l2_gas_amount`)
   - `l2_gas.max_price_per_unit = 0`
   - `l1_gas.max_price_per_unit = min_gas_price` (satisfies the non-zero fee check)
   - `l1_gas.max_amount = 1`
   - Valid Sierra contract class, correct `compiled_class_hash`, valid signature

2. Submit via `starknet_addDeclareTransaction`.

3. `StatelessTransactionValidator::validate` returns `Ok(())` — the `max_l2_gas_amount` branch is skipped for `Declare`.

4. `verify_can_pay_committed_bounds` computes `max_possible_fee = 1 × min_gas_price + 0 × 0 = min_gas_price`, which any funded account can cover.

5. The transaction is admitted to the mempool with `l2_gas.max_amount = u64::MAX`, violating the gateway's admission invariant that no transaction may claim more than `max_l2_gas_amount` L2 gas.

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L154-178)
```rust
    fn validate_tx_extended_calldata_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let total_length = match tx {
            RpcTransaction::Declare(_) => return Ok(()),

            RpcTransaction::DeployAccount(RpcDeployAccountTransaction::V3(tx)) => {
                tx.constructor_calldata.0.len()
            }

            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => {
                tx.calldata.0.len() + tx.proof_facts.0.len()
            }
        };

        if total_length > self.config.max_calldata_length {
            return Err(StatelessTransactionValidatorError::CalldataTooLong {
                calldata_length: total_length,
                max_calldata_length: self.config.max_calldata_length,
            });
        }

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

**File:** crates/apollo_node/resources/config_schema.json (L102-106)
```json
  "batcher_config.static_config.block_builder_config.bouncer_config.block_max_capacity.receipt_l2_gas": {
    "description": "An upper bound on the total receipt-based L2 gas in a block. Includes execution gas plus state allocation costs. Should equal max_block_size.",
    "privacy": "Public",
    "value": 5800000000
  },
```
