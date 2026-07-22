The behavior described in the question is **real and confirmed** by both the production code and an existing test. Let me lay out the evidence precisely.

---

### Title
Missing `max_l2_gas_amount` Enforcement for Declare Transactions Allows Gateway Admission Policy Bypass — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `max_l2_gas_amount` check for `RpcTransaction::Declare` via an empty `if let` branch. A Declare transaction with `l2_gas.max_amount` exceeding the configured limit passes stateless validation unconditionally. The stateful validator does not compensate — it only checks `max_price_per_unit`, never `max_amount`. The behavior is confirmed by an existing test that asserts `Ok(())` for exactly this scenario.

---

### Finding Description

In `validate_resource_bounds`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The `if let RpcTransaction::Declare(_) = tx {}` arm is an empty block — it matches and falls through to `Ok(())` without executing the `else if` branch. The TODO comment confirms this is a known, unresolved gap.

The stateful validator's `validate_resource_bounds` only validates `l2_gas.max_price_per_unit` against the previous block's gas price threshold. It never checks `l2_gas.max_amount` for any transaction type: [2](#0-1) 

The existing test `valid_l2_gas_amount_on_declare` explicitly asserts `Ok(())` for a Declare transaction with `max_amount: GasAmount(200)` against `max_l2_gas_amount: 100`: [3](#0-2) 

By contrast, the same scenario for `DeployAccount` and `Invoke` is correctly rejected, as confirmed by `test_invalid_max_l2_gas_amount` which only parameterizes over those two types: [4](#0-3) 

---

### Impact Explanation

The `max_l2_gas_amount` gateway limit (default: `1,210,000,000`) exists to prevent transactions that declare excessive L2 gas consumption from entering the mempool. For Invoke and DeployAccount, this is enforced. For Declare, it is not. An unprivileged user can submit a Declare transaction with `l2_gas.max_amount = u64::MAX` (or any value above the limit) and it will pass both the stateless and stateful gateway validators and be admitted to the mempool.

The downstream blockifier pre-validation (`check_fee_bounds`, `verify_can_pay_committed_bounds`) will check whether the account can pay `max_amount * max_price_per_unit`. For astronomically large `max_amount` values, this will fail at blockifier validation unless the account holds a correspondingly large balance. However, for values only slightly above `max_l2_gas_amount`, a funded account can satisfy the balance check, resulting in a transaction that bypasses the gateway's admission policy and enters the mempool with a declared L2 gas amount the operator intended to prohibit.

The bouncer tracks actual execution gas (not declared `max_amount`), so block capacity accounting is not directly corrupted. The impact is a gateway admission policy bypass: the operator-configured `max_l2_gas_amount` ceiling is not enforced for Declare transactions.

**Impact category:** High — Mempool/gateway admission accepts transactions that violate the configured resource bound policy.

---

### Likelihood Explanation

Trivially exploitable by any user who can submit an RPC transaction. No special privileges, keys, or state are required. The attacker only needs to construct a valid Declare transaction (valid Sierra class, valid signature, valid nonce) and set `l2_gas.max_amount` above the limit. The existing test already demonstrates the exact proof-of-concept scenario.

---

### Recommendation

Remove the Declare-specific exemption and apply the same `max_l2_gas_amount` check uniformly, or introduce a separate `max_l2_gas_amount_declare` config field if Declare transactions legitimately require a different limit. The TODO comment at line 78 should be resolved:

```rust
// Remove the Declare exemption:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
``` [1](#0-0) 

---

### Proof of Concept

The existing test `valid_l2_gas_amount_on_declare` is already the proof of concept:

- Config: `max_l2_gas_amount: 100`
- Transaction: `RpcTransaction::Declare` with `l2_gas.max_amount: GasAmount(200)`
- Result: `assert_matches!(tx_validator.validate(&tx), Ok(()))` — passes [3](#0-2) 

A standalone Rust unit test matching the question's proof idea would produce identical results, confirming the admission bypass.

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
