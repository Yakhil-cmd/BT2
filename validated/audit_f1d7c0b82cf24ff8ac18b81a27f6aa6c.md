### Title
`StatelessTransactionValidator::validate_resource_bounds` Unconditionally Checks L2 Gas Price, Rejecting Valid L1-Only Transactions at Gateway Admission - (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies a `min_gas_price` floor check unconditionally against `resource_bounds.l2_gas.max_price_per_unit` for every transaction type. A valid L1-only transaction (pre-0.13.3 style, where `l2_gas` is intentionally zero) passes the non-zero fee check but is then rejected with `MaxGasPriceTooLow` because `l2_gas.max_price_per_unit = 0 < min_gas_price (8_000_000_000)`. The stateful validator correctly skips this check for L1Gas transactions, but the stateless validator does not, creating an inconsistency that permanently blocks valid L1-only transactions at the gateway admission boundary.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the validator receives `AllResourceBounds` from `tx.resource_bounds()` and applies two sequential checks:

1. **Zero-fee check** (line 66): wraps the bounds in `ValidResourceBounds::AllResources` and calls `max_possible_fee(Tip::ZERO)`. For a transaction with non-zero L1 gas and zero L2 gas, this evaluates to `l1_gas.max_amount * l1_gas.max_price_per_unit > 0`, so the check **passes**.

2. **Min gas price check** (line 71): unconditionally checks `resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price`. For an L1-only transaction, `l2_gas.max_price_per_unit = 0`, and with the production default `min_gas_price = 8_000_000_000`, this check **fails** with `MaxGasPriceTooLow`. [1](#0-0) 

The stateful validator explicitly handles this case correctly: [2](#0-1) 

The comment `// No validation required for legacy transactions.` at line 385–387 confirms the intent: L1Gas transactions must not be subjected to L2 gas price validation. The stateless validator has no equivalent guard.

The production default `min_gas_price = 8_000_000_000` is set in: [3](#0-2) 

The test suite confirms the discrepancy: the `valid_l1_gas` positive-flow test case is only able to pass by overriding `min_gas_price: 0` in `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING`: [4](#0-3) 

If the production config (`min_gas_price: 8_000_000_000`) were used, this test would fail with `MaxGasPriceTooLow`.

The conversion from `ResourceBoundsMapping` to `ValidResourceBounds` confirms that L1-only transactions (zero L2 gas, zero L1 data gas) are a recognized and supported variant: [5](#0-4) 

### Impact Explanation

Any user submitting a valid L1-only transaction (with non-zero L1 gas but zero L2 gas price) is permanently rejected at the stateless gateway validation stage with `MaxGasPriceTooLow`. The transaction never reaches the mempool or blockifier. This matches the **High** impact: "Mempool/gateway/RPC admission rejects valid transactions before sequencing."

### Likelihood Explanation

Any user or wallet that constructs a V3 transaction with only L1 gas bounds (a supported pre-0.13.3 format) and submits it to the gateway will trigger this rejection. No special privileges are required. The trigger is a standard RPC `add_transaction` call with `AllResourceBounds { l1_gas: non_zero, l2_gas: zero, l1_data_gas: zero }`.

### Recommendation

Mirror the stateful validator's logic: skip the `min_gas_price` check when `l2_gas` is zero (i.e., when the transaction is effectively an L1-only transaction):

```rust
// Only enforce L2 gas price floor when L2 gas is actually used.
if resource_bounds.l2_gas.max_amount.0 > 0 || resource_bounds.l2_gas.max_price_per_unit.0 > 0 {
    if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
        return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
    }
}
```

Alternatively, convert `AllResourceBounds` to `ValidResourceBounds` before the check and match on the variant, consistent with the stateful validator's pattern.

### Proof of Concept

1. Construct an `RpcTransaction::Invoke` with:
   ```
   resource_bounds = AllResourceBounds {
       l1_gas: ResourceBounds { max_amount: 1000, max_price_per_unit: 10_000_000_000 },
       l2_gas: ResourceBounds::default(),   // zero
       l1_data_gas: ResourceBounds::default(), // zero
   }
   ```
2. Submit to the gateway with production config (`min_gas_price = 8_000_000_000`, `validate_resource_bounds = true`).
3. `validate_resource_bounds` evaluates:
   - Zero-fee check: `1000 * 10_000_000_000 > 0` → passes.
   - Min gas price check: `0 < 8_000_000_000` → **fails** with `MaxGasPriceTooLow { gas_price: 0, min_gas_price: 8_000_000_000 }`.
4. The transaction is rejected at the stateless gateway boundary and never reaches the mempool.

The existing test `valid_l1_gas` in `stateless_transaction_validator_test.rs` already demonstrates this path but masks the bug by setting `min_gas_price: 0` in the test config. [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L364-388)
```rust
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
```

**File:** crates/apollo_gateway_config/src/config.rs (L188-204)
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
}
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L69-82)
```rust
#[rstest]
#[case::valid_l1_gas(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l1_gas: NON_EMPTY_RESOURCE_BOUNDS,
            ..Default::default()
        },
        ..Default::default()
    }
)]
```

**File:** crates/apollo_rpc/src/v0_8/transaction.rs (L188-199)
```rust
impl From<ResourceBoundsMapping> for ValidResourceBounds {
    fn from(value: ResourceBoundsMapping) -> Self {
        if value.l1_data_gas.is_zero() && value.l2_gas.is_zero() {
            Self::L1Gas(value.l1_gas)
        } else {
            Self::AllResources(AllResourceBounds {
                l1_gas: value.l1_gas,
                l1_data_gas: value.l1_data_gas,
                l2_gas: value.l2_gas,
            })
        }
    }
```
