Let me look at the key finding more carefully - the `max_l2_gas_amount` check being skipped for Declare transactions, and check if there are downstream guards.

### Title
Declare transactions bypass the `max_l2_gas_amount` gateway admission check, allowing oversized L2 gas bounds into the mempool — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` enforces a `max_l2_gas_amount` cap on `Invoke` and `DeployAccount` transactions but explicitly skips this check for `Declare` transactions. A TODO comment in the source acknowledges the gap. No equivalent downstream guard in the stateful validator or blockifier pre-validation stage closes it for the amount dimension. As a result, any user can submit a `Declare` transaction with an arbitrarily large `l2_gas.max_amount` that passes all gateway checks and is admitted to the mempool.

### Finding Description

In `validate_resource_bounds`, the check reads:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
``` [1](#0-0) 

The production default and the deployed config both set `max_l2_gas_amount = 1_210_000_000`. [2](#0-1) [3](#0-2) 

The test suite explicitly documents and validates this asymmetry. `valid_l2_gas_amount_on_declare` asserts that a `Declare` with `max_amount: GasAmount(200)` passes when `max_l2_gas_amount: 100`, and `test_invalid_max_l2_gas_amount` only exercises `TransactionType::DeployAccount` and `TransactionType::Invoke`, deliberately omitting `Declare`. [4](#0-3) [5](#0-4) 

The stateful validator's `validate_resource_bounds` only checks the L2 gas **price** threshold against the previous block, not the gas **amount**: [6](#0-5) 

The blockifier's `perform_pre_validation_stage` calls `check_fee_bounds` (which checks that bounds are *sufficient* to cover minimal gas, not that they are *too high*) and `verify_can_pay_committed_bounds` (which checks account balance against `max_amount × max_price`). Neither enforces the gateway's `max_l2_gas_amount` policy. [7](#0-6) 

Critically, `initial_sierra_gas` for execution is derived directly from `l2_gas.max_amount` in `AllResources` bounds, capped only by the OS-level constants `validate_max_sierra_gas = 100_000_000` and `execute_max_sierra_gas = 1_110_000_000` (which sum to exactly `1_210_000_000` — the gateway limit). A `Declare` transaction with `l2_gas.max_amount` set to any value above `1_210_000_000` but below what the account balance can cover passes every check and enters the mempool with a gas budget that the gateway was designed to reject. [8](#0-7) 

### Impact Explanation

The gateway's `max_l2_gas_amount` is the sole stateless guard preventing transactions with oversized L2 gas bounds from entering the mempool. For `Invoke` and `DeployAccount` it is enforced; for `Declare` it is not. Any caller can submit a `Declare` transaction with `l2_gas.max_amount` exceeding `1_210_000_000` and have it admitted to the mempool without restriction. This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

The `verify_can_pay_committed_bounds` check in the blockifier provides a partial backstop only when the account's balance is insufficient to cover `max_amount × max_price`. For values only modestly above the limit (e.g., `1_210_000_001`) with a sufficiently funded account, the transaction clears every check end-to-end, bypassing the admission policy entirely.

### Likelihood Explanation

The trigger requires no privilege. Any user who can submit a `Declare` transaction can set `l2_gas.max_amount` to an arbitrary value. The bypass is stateless and requires no special account state beyond having enough balance to satisfy `verify_can_pay_committed_bounds` for the chosen amount. The TODO comment in the source confirms the developers are aware the check is absent.

### Recommendation

Remove the `if let RpcTransaction::Declare(_) = tx { }` branch that silently skips the check, and apply the `max_l2_gas_amount` guard uniformly to all three transaction types:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Update `test_invalid_max_l2_gas_amount` to include `TransactionType::Declare` in its `#[values(...)]` list, and remove the `valid_l2_gas_amount_on_declare` test (or convert it to an error-case test).

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with `resource_bounds.l2_gas.max_amount = GasAmount(1_210_000_001)` and `resource_bounds.l2_gas.max_price_per_unit = GasPrice(min_gas_price)`.
2. Submit it to the gateway's `add_tx` endpoint.
3. `StatelessTransactionValidator::validate` reaches `validate_resource_bounds`; the `if let RpcTransaction::Declare(_) = tx { }` branch fires and the `MaxGasAmountTooHigh` error is never returned.
4. The stateful validator's `validate_resource_bounds` checks only the L2 gas price threshold — the amount is not examined.
5. `validate_by_mempool` and `skip_stateful_validations` run without inspecting the gas amount.
6. `run_validate_entry_point` executes the Declare fully via `StatefulValidator::execute`; `verify_can_pay_committed_bounds` passes if the account holds at least `1_210_000_001 × min_gas_price` STRK.
7. The transaction is accepted into the mempool with `l2_gas.max_amount` above the gateway's stated policy limit, violating the admission invariant that `max_l2_gas_amount` enforces for all other transaction types. [9](#0-8) [10](#0-9)

### Citations

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

**File:** crates/apollo_deployments/resources/app_configs/replacer_gateway_config.json (L25-25)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": 1210000000,
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
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

**File:** crates/blockifier/src/fee/fee_test.rs (L388-414)
```rust
#[rstest]
#[case::default(
    VersionedConstants::create_for_account_testing().initial_gas_no_user_l2_bound().0,
    GasVectorComputationMode::NoL2Gas
)]
#[case::from_l2_gas(4321, GasVectorComputationMode::All)]
fn test_initial_sierra_gas(
    #[case] expected: u64,
    #[case] gas_mode: GasVectorComputationMode,
    block_context: BlockContext,
) {
    let resource_bounds = match gas_mode {
        GasVectorComputationMode::NoL2Gas => ValidResourceBounds::L1Gas(ResourceBounds {
            max_amount: GasAmount(1234),
            max_price_per_unit: GasPrice(56),
        }),
        GasVectorComputationMode::All => ValidResourceBounds::AllResources(AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(expected),
                max_price_per_unit: GasPrice(1),
            },
            ..Default::default()
        }),
    };
    let account_tx = invoke_tx_with_default_flags(invoke_tx_args!(resource_bounds));
    let actual = block_context.to_tx_context(&account_tx).initial_sierra_gas().0;
    assert_eq!(actual, expected)
```
