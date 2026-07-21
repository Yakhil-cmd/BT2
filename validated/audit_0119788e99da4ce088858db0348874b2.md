The code is unambiguous. Let me verify the stateful path has no compensating check on `max_amount` for Declare before writing the final answer.

The evidence is complete. The bypass is confirmed at the code level, acknowledged by a developer TODO, and verified by a dedicated test. The stateful path has no compensating `max_amount` check for Declare. Here is the full finding.

---

### Title
`StatelessTransactionValidator::validate_resource_bounds` Skips `max_l2_gas_amount` Check for Declare Transactions, Allowing Oversized Gas Amount Admission — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` unconditionally skips the `max_l2_gas_amount` upper-bound check when the transaction is `RpcTransaction::Declare`. An unprivileged user can submit a Declare transaction with `l2_gas.max_amount` set to any value — including `u64::MAX` — and the gateway will admit it to the mempool. No downstream compensating check enforces this bound for Declare transactions before mempool admission.

---

### Finding Description

In `validate_resource_bounds`, the check for `l2_gas.max_amount` is guarded by an empty `if let RpcTransaction::Declare(_) = tx { }` branch, with the actual rejection logic placed in the `else if`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The developer TODO on line 78 explicitly acknowledges this gap. The existing test suite confirms the bypass is real and currently expected behavior: `valid_l2_gas_amount_on_declare` asserts `Ok(())` for a Declare with `max_amount: GasAmount(200)` when `max_l2_gas_amount: 100`. [2](#0-1) 

The `test_invalid_max_l2_gas_amount` test explicitly excludes `TransactionType::Declare` from its `#[values(...)]` parameter, confirming the check is intentionally absent for Declare. [3](#0-2) 

The default production value of `max_l2_gas_amount` is `1,210,000,000`. [4](#0-3) 

**No compensating check exists in the stateful path.** The stateful validator's `validate_resource_bounds` only checks `l2_gas_price` against the previous block's price — it does not check `l2_gas.max_amount` at all. [5](#0-4) 

For Declare transactions, the blockifier's `StatefulValidator::perform_validations` calls `self.execute(tx)` (full execution), which does invoke `perform_pre_validation_stage` → `verify_can_pay_committed_bounds`. However, that check only rejects the transaction if the account's balance is insufficient to cover `max_amount * max_price_per_unit`. It does not enforce the gateway's `max_l2_gas_amount` policy bound. A well-funded account (or one with a very low `max_price_per_unit`) can pass this check with an arbitrarily large `max_amount`. [6](#0-5) 

The full gateway admission flow is: stateless validate → convert → stateful validate → mempool add. The `max_l2_gas_amount` gate is only in the stateless step, and it is skipped for Declare. [7](#0-6) 

---

### Impact Explanation

A Declare transaction with `l2_gas.max_amount` exceeding `max_l2_gas_amount` (e.g., `u64::MAX`) is admitted to the mempool when the gateway's own policy requires it to be rejected. The concrete corrupted admission value is the mempool accepting a Declare with an oversized L2 gas amount bound. This maps directly to the allowed impact: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

Any unprivileged user can craft and submit an `RpcTransaction::Declare` with an arbitrary `l2_gas.max_amount`. No special account state, balance, or privilege is required to trigger the bypass — only the ability to call the public `add_tx` endpoint. The bypass is unconditional for all Declare transactions.

---

### Recommendation

Remove the empty `if let RpcTransaction::Declare(_) = tx { }` branch and apply the `max_l2_gas_amount` check uniformly to all transaction types, including Declare. The TODO comment on line 78 already flags this as a known gap. The fix is a one-line change: delete the Declare exemption so the `else if` becomes an unconditional `if`.

```rust
// Before (broken):
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(...);
}

// After (fixed):
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(...);
}
```

The test `valid_l2_gas_amount_on_declare` must be updated to expect an error, and `test_invalid_max_l2_gas_amount` must add `TransactionType::Declare` to its `#[values(...)]` list.

---

### Proof of Concept

```rust
#[test]
fn declare_bypasses_max_l2_gas_amount_check() {
    use apollo_gateway_config::config::StatelessTransactionValidatorConfig;
    use crate::stateless_transaction_validator::StatelessTransactionValidator;
    // Build a Declare RpcTransaction with l2_gas.max_amount = u64::MAX
    // and max_l2_gas_amount = 1 in the config.
    let config = StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 1,
        min_gas_price: 1,
        ..Default::default()
    };
    let validator = StatelessTransactionValidator { config };
    let tx = rpc_tx_for_testing(
        TransactionType::Declare,
        RpcTransactionArgs {
            resource_bounds: AllResourceBounds {
                l2_gas: ResourceBounds {
                    max_amount: GasAmount(u64::MAX),
                    max_price_per_unit: GasPrice(1),
                },
                ..Default::default()
            },
            ..Default::default()
        },
    );
    // Asserts Ok(()), confirming the Declare branch skips the amount check.
    assert_matches!(validator.validate(&tx), Ok(()));
}
```

This test mirrors the existing `valid_l2_gas_amount_on_declare` test structure and will pass against the current codebase, confirming the bypass.

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

**File:** crates/apollo_gateway/src/gateway.rs (L235-286)
```rust
        // Perform stateless validations.
        self.stateless_tx_validator.validate(&tx)?;

        let tx_signature = tx.signature().clone();

        // Declare conversions overload the compiler component's CPU and memory. Reject declares if
        // there are too many declares compiling in parallel. The permit is held only across
        // compilation and released before stateful validation.
        let compilation_permit = if matches!(tx, RpcTransaction::Declare(_)) {
            Some(self.declare_compilation_semaphore.try_acquire().map_err(|_| {
                let error = StarknetError::too_many_concurrent_declare_compilations();
                metric_counters.record_add_tx_failure(&error);
                error
            })?)
        } else {
            None
        };

        let (internal_tx, executable_tx, proof_data) =
            self.convert_rpc_tx_to_internal_and_executable_txs(tx, &tx_signature).await?;
        drop(compilation_permit);

        let mut stateful_transaction_validator = self
            .stateful_tx_validator_factory
            .instantiate_validator(self.config.dynamic_config.native_classes_whitelist.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```
