### Title
Gateway Stateless Validator Skips `max_l2_gas_amount` Check for Declare Transactions, Admitting Over-Bound Transactions to Mempool - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary
`StatelessTransactionValidator::validate_resource_bounds` contains an explicit no-op branch that exempts `RpcTransaction::Declare` from the `max_l2_gas_amount` upper-bound check. Any Declare transaction with `l2_gas.max_amount` exceeding the configured limit (1,210,000,000 by default) passes all gateway validation stages and is admitted to the mempool, violating the gateway's own admission invariant.

### Finding Description
In `validate_resource_bounds`, the check for `max_l2_gas_amount` is structured as:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The `if let RpcTransaction::Declare(_) = tx {}` arm is a deliberate no-op: it matches Declare transactions and does nothing, causing the entire `max_l2_gas_amount` guard to be skipped. The TODO comment acknowledges the gap. The test `valid_l2_gas_amount_on_declare` explicitly documents and asserts this bypass: [2](#0-1) 

The stateful validator's `validate_resource_bounds` only checks `l2_gas.max_price_per_unit` against the previous block price — it never checks `max_amount`: [3](#0-2) 

Therefore a Declare transaction with `l2_gas.max_amount = u64::MAX` (or any value above `max_l2_gas_amount`) clears both the stateless and stateful gateway paths and is forwarded to the mempool via `add_tx_inner`: [4](#0-3) 

The production config sets `max_l2_gas_amount = 1,210,000,000` for all other transaction types: [5](#0-4) 

### Impact Explanation
The gateway's admission invariant — "every admitted transaction must have `l2_gas.max_amount ≤ max_l2_gas_amount`" — is broken for Declare transactions. An attacker can submit Declare transactions with arbitrarily large `l2_gas.max_amount` values that pass all gateway checks and enter the mempool. The batcher will later pick them up; `perform_pre_validation_stage` will call `verify_can_pay_committed_bounds`, which will reject them because no account holds `u64::MAX × min_gas_price` STRK. However, the gateway's own admission control is bypassed, matching the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing." [6](#0-5) 

### Likelihood Explanation
Any unprivileged user can trigger this. The only requirements are a syntactically valid Declare transaction (valid Sierra class, valid nonce, `max_price_per_unit ≥ min_gas_price`) with `l2_gas.max_amount` set above the configured limit. No special account privileges or prior state are needed.

### Recommendation
Remove the no-op `if let RpcTransaction::Declare(_) = tx {}` branch and apply the `max_l2_gas_amount` check uniformly to all transaction types. If Declare transactions legitimately require a higher gas ceiling, introduce a separate `max_l2_gas_amount_declare` config key rather than removing the bound entirely.

### Proof of Concept
Construct an `RpcDeclareTransactionV3` with:
- `l2_gas.max_amount = GasAmount(u64::MAX)` (or any value > 1,210,000,000)
- `l2_gas.max_price_per_unit ≥ GasPrice(8_000_000_000)` (satisfies `min_gas_price`)
- A valid Sierra contract class, correct nonce, and a funded sender account

Submit via the HTTP gateway. `StatelessTransactionValidator::validate` reaches the `validate_resource_bounds` call, enters the `if let RpcTransaction::Declare(_) = tx {}` no-op branch, and returns `Ok(())` without checking the amount. The stateful validator likewise passes. The transaction is forwarded to the mempool, violating the `max_l2_gas_amount` admission bound that applies to every other transaction type.

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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
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
