### Title
Missing `max_l2_gas_amount` Upper-Bound Check for `Declare` Transactions Allows Unbounded L2 Gas Admission - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The gateway's stateless validator enforces a `max_l2_gas_amount` ceiling on every transaction type **except** `Declare`. An explicit `if let RpcTransaction::Declare(_) = tx { }` branch skips the check entirely, with a `TODO` comment acknowledging the gap. An unprivileged user can submit a `Declare` transaction whose `l2_gas.max_amount` is set to `u64::MAX` (or any arbitrarily large value). The gateway admits the transaction, the stateful validator does not re-check the gas amount ceiling, and the transaction enters the mempool and is forwarded to the blockifier for full execution — including Sierra-to-CASM compilation — with an unbounded L2 gas budget declared by the sender.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the code reads:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
```

The `if let RpcTransaction::Declare(_) = tx { }` arm is an intentional no-op: it matches `Declare` and does nothing, so the `else if` branch that enforces `max_l2_gas_amount` is never reached for `Declare` transactions. The production default for `max_l2_gas_amount` is `1_210_000_000` (≈ 1.21 × 10⁹ gas units). A `Declare` transaction can carry `l2_gas.max_amount = u64::MAX` (≈ 1.84 × 10¹⁹) and pass this check.

The stateful validator (`StatefulTransactionValidator::validate_resource_bounds`) only checks the L2 gas **price** against the previous block's price; it does not check the gas **amount** ceiling at all. No downstream guard in the blockifier pre-validation stage (`perform_pre_validation_stage` → `check_fee_bounds`) rejects a `Declare` transaction solely because its declared `max_amount` is astronomically large — `check_fee_bounds` only verifies that the declared amount is ≥ the estimated minimum, not that it is ≤ some protocol maximum.

The test `valid_l2_gas_amount_on_declare` in `stateless_transaction_validator_test.rs` explicitly confirms this is the current, tested behavior: a `Declare` with `max_amount = 200` when the configured limit is `100` passes validation without error.

### Impact Explanation

**Impact: High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

A `Declare` transaction with `l2_gas.max_amount = u64::MAX` is admitted through the gateway stateless check, passes the stateful check (which only validates gas price, not gas amount), and enters the mempool. The transaction hash is computed over the unbounded `max_amount` field, so the admitted transaction carries a hash that commits to an economically nonsensical gas bound. When the batcher selects the transaction for execution, the blockifier's `verify_can_pay_committed_bounds` computes `max_possible_fee = max_amount × max_price_per_unit`, which overflows or produces an astronomically large fee requirement, potentially causing the balance check to behave incorrectly or the transaction to be incorrectly accepted/rejected at execution time. Additionally, the `Declare` path in the stateful validator runs full execution (including Sierra-to-CASM compilation) rather than just the validate entry point, meaning the sequencer expends real CPU resources on a transaction that should have been rejected at the gate.

### Likelihood Explanation

Any unprivileged user with a valid Starknet account can submit a `Declare` transaction via the public RPC endpoint. The `l2_gas.max_amount` field is a plain `u64` in the RPC transaction struct and is freely settable by the caller. No authentication or privilege is required. The bypass is deterministic and 100% reproducible.

### Recommendation

Remove the `if let RpcTransaction::Declare(_) = tx { }` no-op branch and apply the same `max_l2_gas_amount` ceiling to `Declare` transactions as is applied to `Invoke` and `DeployAccount`. The TODO comment at line 78 of `stateless_transaction_validator.rs` should be resolved by adding the check rather than deferring it.

```rust
// Apply max_l2_gas_amount to all transaction types including Declare.
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with a well-formed Sierra contract class and set `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and `resource_bounds.l2_gas.max_price_per_unit` at or above `min_gas_price`.
2. Submit to the gateway's `add_tx` endpoint.
3. Observe that `StatelessTransactionValidator::validate` returns `Ok(())` — confirmed by the existing test `valid_l2_gas_amount_on_declare` which passes `max_amount = 200` against a limit of `100` for `TransactionType::Declare`.
4. The transaction proceeds through `StatefulTransactionValidator::extract_state_nonce_and_run_validations`, which checks only the L2 gas **price** (not amount) and nonce, then runs full blockifier execution (Sierra-to-CASM compilation + constructor execution) with the unbounded gas budget.

The root cause is at: [1](#0-0) 

Confirmed by the intentional positive test: [2](#0-1) 

The production default that is bypassed: [3](#0-2) 

The stateful validator's resource-bounds check (gas amount not checked): [4](#0-3)

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
