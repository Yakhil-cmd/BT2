### Title
`max_l2_gas_amount` Limit Not Enforced for Declare Transactions at Gateway Admission — (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidatorConfig::max_l2_gas_amount` is defined, documented, and enforced for `Invoke` and `DeployAccount` transactions, but is **explicitly skipped** for `Declare` transactions in `validate_resource_bounds`. A TODO comment in the source acknowledges the gap. No downstream guard in the stateful validator, blockifier pre-validation, or bouncer enforces an upper bound on the declared `l2_gas.max_amount` for Declare transactions. Any unprivileged user can submit a Declare transaction with `l2_gas.max_amount = u64::MAX` and it will pass all gateway checks and be admitted to the mempool.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the check for `l2_gas.max_amount` against `config.max_l2_gas_amount` contains an explicit early-return for Declare transactions:

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

The config field `max_l2_gas_amount` has a production default of `1_210_000_000`: [2](#0-1) 

The test `valid_l2_gas_amount_on_declare` explicitly confirms that a Declare transaction with `max_amount: GasAmount(200)` passes validation even when `max_l2_gas_amount: 100` is configured — i.e., the bypass is tested and known: [3](#0-2) 

The test for the enforced path (`test_invalid_max_l2_gas_amount`) only covers `TransactionType::DeployAccount` and `TransactionType::Invoke`, confirming Declare is intentionally excluded: [4](#0-3) 

**Downstream path has no compensating guard:**

- The stateful validator's `validate_resource_bounds` only checks the L2 gas *price* against the previous block's price, not the `max_amount` upper bound: [5](#0-4) 

- The blockifier's `check_fee_bounds` (`perform_pre_validation_stage`) only checks that `resource_bounds.max_amount >= minimal_gas_amount` (a lower-bound check), never an upper-bound check: [6](#0-5) 

- The bouncer checks actual *execution* gas against block limits, not the declared `max_amount` field in the transaction: [7](#0-6) 

The OS does cap execution gas at `VALIDATE_MAX_SIERRA_GAS` regardless of the declared `max_amount` (line 801 of `transaction_impls.cairo`), so execution itself is safe. However, the gateway admission invariant — that every admitted transaction has `l2_gas.max_amount ≤ max_l2_gas_amount` — is broken for Declare transactions.

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The `max_l2_gas_amount` limit is the gateway's per-transaction DoS protection for L2 gas. Its purpose is to prevent transactions from claiming more gas than the block can accommodate (block `sierra_gas` cap is `5,000,000,000`; per-tx limit is `1,210,000,000`). By bypassing this check for Declare transactions, an attacker can:

1. Submit Declare transactions with `l2_gas.max_amount = u64::MAX` (18,446,744,073,709,551,615).
2. These transactions pass all gateway stateless and stateful checks and are admitted to the mempool.
3. The mempool and batcher must process these transactions, and the batcher's bouncer only rejects based on actual execution gas — not the declared `max_amount` — so the transaction is not dropped at the block-building stage either.

The invariant "all admitted transactions satisfy `l2_gas.max_amount ≤ max_l2_gas_amount`" is broken for the Declare transaction type, making the configured limit ineffective for that type.

### Likelihood Explanation

**Likelihood: High.** The bypass requires no privilege — any user can submit a Declare transaction via the public gateway endpoint. The bypassed code path is reachable on every Declare submission. The TODO comment and the dedicated test `valid_l2_gas_amount_on_declare` confirm the developers are aware of the gap but have not yet closed it.

### Recommendation

Apply the `max_l2_gas_amount` check to Declare transactions by removing the early-return branch:

```rust
// Remove the Declare exemption:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher L2 gas ceiling (e.g., because `__validate_declare__` can consume more gas than a typical invoke), introduce a separate `max_l2_gas_amount_declare` config field rather than removing the check entirely.

### Proof of Concept

1. Construct a valid `RpcDeclareTransaction::V3` with `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and a valid Sierra class.
2. Submit it to the gateway's `add_tx` endpoint.
3. The stateless validator's `validate_resource_bounds` hits the `if let RpcTransaction::Declare(_) = tx { }` branch and returns `Ok(())` without checking `max_amount`.
4. The stateful validator checks only the gas *price*, not the gas *amount* upper bound.
5. The transaction is forwarded to the mempool and admitted — despite `max_l2_gas_amount` being set to `1_210_000_000` in production config.

The existing test already demonstrates this:
```rust
// config: max_l2_gas_amount = 100, tx: max_amount = 200 → Ok(()) for Declare
assert_matches!(tx_validator.validate(&tx), Ok(()));
``` [3](#0-2)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L427-458)
```rust
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```

**File:** crates/blockifier/src/bouncer.rs (L125-137)
```rust
    pub fn within_max_capacity_or_err(
        &self,
        weights: BouncerWeights,
    ) -> TransactionExecutionResult<()> {
        if self.block_max_capacity.has_room(weights) {
            Ok(())
        } else {
            Err(TransactionExecutionError::TransactionTooLarge {
                max_capacity: Box::new(self.block_max_capacity),
                tx_size: Box::new(weights),
            })
        }
    }
```
