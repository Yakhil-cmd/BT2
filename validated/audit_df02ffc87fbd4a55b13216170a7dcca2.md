### Title
Missing `max_l2_gas_amount` Admission Check for Declare Transactions in Gateway Stateless Validator - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary
`StatelessTransactionValidator::validate_resource_bounds` enforces the `max_l2_gas_amount` cap for `Invoke` and `DeployAccount` transactions but explicitly skips it for `Declare` transactions. An unprivileged user can submit a `Declare` transaction with `l2_gas.max_amount` exceeding the configured limit and have it admitted through the gateway into the mempool.

### Finding Description
In `validate_resource_bounds`, the check for `l2_gas.max_amount > self.config.max_l2_gas_amount` is guarded by a type branch that silently passes all `Declare` transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← no check, falls through
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

The default `max_l2_gas_amount` is `1_210_000_000`. A `Declare` transaction with `l2_gas.max_amount = 1_210_000_001` (or any value above the limit) passes this function without error. The test `valid_l2_gas_amount_on_declare` explicitly confirms this: a Declare with `max_amount: GasAmount(200)` passes when `max_l2_gas_amount: 100`.

The stateful validator's `validate_resource_bounds` only checks the L2 gas **price** against the previous block's price, not the **amount**. `verify_can_pay_committed_bounds` checks `max_amount * max_price_per_unit <= balance`, which is satisfiable by an attacker who holds sufficient balance. No other guard in the admission path rejects a Declare with an over-limit `l2_gas.max_amount`.

### Impact Explanation
A `Declare` transaction with `l2_gas.max_amount` just above `max_l2_gas_amount` (e.g., `max_l2_gas_amount + 1`) and a `max_price_per_unit` meeting the stateful threshold is admitted to the mempool. This breaks the gateway's own admission invariant: "no transaction with `l2_gas.max_amount > max_l2_gas_amount` should be accepted." The mempool receives transactions that the operator has explicitly configured to reject, undermining the resource-bound admission policy for the most resource-intensive transaction type (class declaration with Sierra compilation).

### Likelihood Explanation
Any user can craft a `Declare` transaction with an over-limit `l2_gas.max_amount`. The only prerequisite is holding enough fee-token balance to satisfy `verify_can_pay_committed_bounds`. The gap is acknowledged in the source with a TODO comment and is confirmed by a dedicated positive test case, meaning it is a known, reachable, and untriggered code path.

### Recommendation
Remove the `Declare` exception in `validate_resource_bounds` and apply the same `max_l2_gas_amount` check uniformly to all transaction types, or add a separate, appropriately-sized cap for Declare transactions if their gas profile justifies a different limit:

```rust
// Apply to all transaction types, including Declare.
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

### Proof of Concept
1. Construct a V3 `Declare` transaction with:
   - `l2_gas.max_amount = max_l2_gas_amount + 1` (e.g., `1_210_000_001`)
   - `l2_gas.max_price_per_unit` ≥ stateful threshold (e.g., `min_gas_price_percentage`% of previous block L2 gas price)
   - Sufficient fee-token balance to cover `max_amount * max_price_per_unit`
2. Submit to the gateway `add_tx` endpoint.
3. `StatelessTransactionValidator::validate` calls `validate_resource_bounds`, which hits the `if let RpcTransaction::Declare(_) = tx { }` branch and returns `Ok(())` without checking the amount.
4. Stateful validation passes (price check only; balance check passes with sufficient funds).
5. Transaction is forwarded to the mempool — admitted despite exceeding the configured `max_l2_gas_amount` limit.

The existing test `valid_l2_gas_amount_on_declare` in `stateless_transaction_validator_test.rs` already demonstrates this path passes with `max_amount: GasAmount(200)` against `max_l2_gas_amount: 100`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
        match tx_resource_bounds {
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
                    return Err(StarknetError {
                        // We didn't have this kind of an error.
                        code: StarknetErrorCode::UnknownErrorCode(
                            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
                        ),
                        message: format!(
                            "Transaction L2 gas price {tx_l2_gas_price} is below the required \
                             threshold {threshold}.",
                        ),
                    });
                }
            }
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
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
