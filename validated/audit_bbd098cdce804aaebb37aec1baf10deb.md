### Title
`Declare` Transactions Bypass `max_l2_gas_amount` Stateless Validation, Allowing Unbounded L2 Gas Admission — (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. Any user can submit a `Declare` transaction with `l2_gas.max_amount = u64::MAX` and it will pass the stateless gateway filter, bypassing the admission guard that exists for every other transaction type.

### Finding Description

In `validate_resource_bounds`, the L2 gas amount ceiling is enforced for `Invoke` and `DeployAccount` transactions but is silently skipped for `Declare`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← nothing: no upper-bound check at all
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The default production ceiling is `max_l2_gas_amount = 1_210_000_000`. [2](#0-1) 

The gap is confirmed by a dedicated test that asserts a `Declare` transaction with `max_amount = 200` passes when the config ceiling is `100`: [3](#0-2) 

The stateless validator is the cheap, first-line admission filter. Its purpose is to reject structurally invalid or policy-violating transactions before the more expensive stateful path (nonce lookup, blockifier validation, balance check) is invoked. The `max_l2_gas_amount` limit exists precisely to prevent a single transaction from claiming an unreasonably large share of the block's L2 gas budget at admission time.

Because the check is absent for `Declare`, an attacker can craft a `Declare` transaction with:
- `l2_gas.max_amount = u64::MAX` (18,446,744,073,709,551,615)
- `l2_gas.max_price_per_unit = min_gas_price` (8,000,000,000 — the minimum required to pass the price check)

This transaction passes every stateless check:
1. `validate_contract_address` — passes (sender address is valid)
2. `validate_empty_account_deployment_data` — passes
3. `validate_empty_paymaster_data` — passes
4. `validate_resource_bounds` — passes (`ZeroResourceBounds` check passes because `max_possible_fee > 0`; `MaxGasPriceTooLow` passes; `MaxGasAmountTooHigh` is **skipped** for Declare)
5. `validate_tx_size` — passes (calldata/signature within limits)
6. `validate_nonce_data_availability_mode` / `validate_fee_data_availability_mode` — pass
7. `validate_declare_tx` — passes (Sierra version, class length, entry points) [4](#0-3) 

The transaction is then forwarded to the stateful validator (`extract_state_nonce_and_run_validations`), which performs the expensive nonce lookup and blockifier pre-validation. [5](#0-4) 

Inside `perform_pre_validation_stage`, `verify_can_pay_committed_bounds` will ultimately reject the transaction because no realistic account holds a balance of `u64::MAX × 8_000_000_000` STRK. However, the stateless filter — which is supposed to prevent this work — has already been bypassed. [6](#0-5) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The stateless validator is the gateway's cheap, first-line filter. By bypassing it, an attacker forces the sequencer to perform expensive stateful work (state reads, blockifier validation, balance checks) for every crafted `Declare` transaction. This is a targeted DoS against the stateful validation path. The asymmetry is exact: the same `max_l2_gas_amount = 1_210_000_000 + 1` value is rejected for `Invoke`/`DeployAccount` at the stateless layer but admitted for `Declare`.

The corrupted value is the admission decision: the stateless validator returns `Ok(())` (admitted) for a `Declare` transaction that should return `Err(MaxGasAmountTooHigh)`.

### Likelihood Explanation

Any unprivileged user can submit a `Declare` transaction. The crafted transaction requires only a valid Sierra class (which can be minimal) and a sender address. No special privileges, keys, or on-chain state are required to trigger the bypass. The attack is trivially repeatable.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to `Declare` transactions. Remove the empty `if let RpcTransaction::Declare(_) = tx {}` branch and the associated TODO, replacing the conditional with a uniform check across all transaction types:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Update the test `valid_l2_gas_amount_on_declare` to assert that a `Declare` transaction with `max_amount` exceeding the configured ceiling is **rejected**, consistent with the behavior tested for `Invoke` and `DeployAccount` in `test_invalid_max_l2_gas_amount`. [7](#0-6) 

### Proof of Concept

1. Construct a minimal valid `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = GasAmount(u64::MAX)`
   - `l2_gas.max_price_per_unit = GasPrice(DEFAULT_VALIDATOR_CONFIG.min_gas_price)` (satisfies the price floor)
   - Any valid Sierra class, valid sender address, valid nonce/DA modes

2. Call `StatelessTransactionValidator { config: DEFAULT_VALIDATOR_CONFIG }.validate(&tx)`.

3. Observe `Ok(())` — the transaction is admitted despite `u64::MAX >> max_l2_gas_amount (1_210_000_000)`.

4. For comparison, construct the same transaction as `RpcInvokeTransaction::V3` with identical resource bounds. Call `validate`. Observe `Err(MaxGasAmountTooHigh { gas_amount: GasAmount(u64::MAX), max_gas_amount: 1_210_000_000 })`.

The asymmetry is the vulnerability: identical resource bounds are admitted for `Declare` and rejected for `Invoke`. [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L56-88)
```rust
    fn validate_resource_bounds(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        if !self.config.validate_resource_bounds {
            return Ok(());
        }

        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }

        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }

        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L193-193)
```rust
            max_l2_gas_amount: 1_210_000_000,
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
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
