### Title
Missing `max_l2_gas_amount` Bound Check for `Declare` Transactions Allows Gateway Admission Bypass — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds()` explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. Any account with sufficient STRK balance can submit a `Declare` transaction with an arbitrarily large `l2_gas.max_amount`, bypassing the gateway's admission control and entering the mempool with a resource-bound value that violates the enforced protocol limit for every other transaction type.

### Finding Description

In `crates/apollo_gateway/src/stateless_transaction_validator.rs`, `validate_resource_bounds()` enforces that `l2_gas.max_amount ≤ config.max_l2_gas_amount` (default 1,210,000,000) for `Invoke` and `DeployAccount` transactions, but the check is explicitly skipped for `Declare` with an acknowledged TODO:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The test `valid_l2_gas_amount_on_declare` explicitly confirms this bypass is intentional and tested: [2](#0-1) 

The stateful validator's `validate_resource_bounds()` only checks `l2_gas.max_price_per_unit` against the previous block's L2 gas price threshold — it performs **no** check on `l2_gas.max_amount`: [3](#0-2) 

The only downstream guard is `verify_can_pay_committed_bounds` in `perform_pre_validation_stage`, which checks `balance ≥ max_possible_fee`: [4](#0-3) 

`max_possible_fee` for `AllResources` is `l1_gas.max_amount × l1_gas.max_price + l2_gas.max_amount × (l2_gas.max_price + tip) + l1_data_gas.max_amount × l1_data_gas.max_price`: [5](#0-4) 

This balance guard is **not** equivalent to the missing admission check. A well-funded account (e.g., a large DeFi protocol or foundation wallet) with balance ≥ `(max_l2_gas_amount + 1) × min_gas_price ≈ 1,210,000,001 × 8,000,000,000 ≈ 9.68 × 10¹⁸ STRK units` can submit a `Declare` transaction with `l2_gas.max_amount` exceeding the gateway limit, pass both stateless and stateful validation, and be admitted to the mempool — a path that is explicitly blocked for `Invoke` and `DeployAccount`.

### Impact Explanation

Matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** A `Declare` transaction with `l2_gas.max_amount > max_l2_gas_amount` is invalid by the gateway's own admission rules (the limit exists precisely to bound per-transaction L2 gas claims). Admitting such a transaction to the mempool violates the invariant enforced for all other transaction types. Once in the mempool, the batcher will attempt execution with an initial gas budget derived from the oversized bound, and the bouncer must absorb the cost of discovering the transaction cannot fit within block limits at execution time rather than at admission time.

### Likelihood Explanation

Low-to-medium. Requires a sender account whose STRK balance covers `l2_gas.max_amount × l2_gas.max_price_per_unit`. For amounts only slightly above the limit (e.g., `max_l2_gas_amount + 1`), the required balance is large but reachable by protocol-level accounts. The attack surface is further constrained by `reject_future_declare_txs = true` (default), which requires the nonce to match exactly, limiting spam to one transaction per nonce increment. [6](#0-5) 

### Recommendation

Remove the `Declare` exception in `validate_resource_bounds()` and apply the same `max_l2_gas_amount` upper-bound check to `Declare` transactions, resolving the acknowledged TODO:

```rust
// Remove the Declare bypass:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If `Declare` transactions legitimately require a higher L2 gas ceiling (e.g., for large Sierra programs), introduce a separate `max_l2_gas_amount_declare` configuration parameter rather than removing the check entirely.

### Proof of Concept

1. Create an account with STRK balance ≥ `(max_l2_gas_amount + 1) × min_gas_price`.
2. Submit an `RpcTransaction::Declare` with:
   - `resource_bounds.l2_gas.max_amount = GasAmount(max_l2_gas_amount + 1)` (e.g., `1_210_000_001`)
   - `resource_bounds.l2_gas.max_price_per_unit = GasPrice(min_gas_price)` (e.g., `8_000_000_000`)
   - All other fields valid.
3. Observe that `StatelessTransactionValidator::validate()` returns `Ok(())` — the `MaxGasAmountTooHigh` error is never raised for `Declare`.
4. Observe that `StatefulTransactionValidator::extract_state_nonce_and_run_validations()` also returns `Ok(nonce)` because `verify_can_pay_committed_bounds` passes (balance is sufficient) and no other check enforces `max_l2_gas_amount` for `Declare`.
5. The transaction is forwarded to the mempool via `mempool_client.add_tx(…)` with `l2_gas.max_amount` exceeding the gateway's stated limit — a path that would have been rejected at step 3 for any `Invoke` or `DeployAccount` transaction with the same bounds. [7](#0-6)

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

**File:** crates/starknet_api/src/transaction/fields.rs (L393-414)
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
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L235-266)
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
```
