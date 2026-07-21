### Title
Gateway Stateless Validator Unconditionally Applies L2 Gas Price Floor to Transactions with Zero L2 Gas Bounds, Causing Valid Transactions to Be Rejected - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies the `min_gas_price` check unconditionally to every incoming transaction — including those that carry only L1 or L1-data-gas bounds and therefore have `l2_gas.max_price_per_unit = 0`. The production default is `min_gas_price = 8_000_000_000` (8 Gwei). Any transaction whose L2 gas price is zero is rejected at the gateway with `MaxGasPriceTooLow`, even though the transaction may carry perfectly valid L1 gas bounds. The unit-test suite masks this entirely by using a testing config that sets `min_gas_price = 0`.

### Finding Description

In `validate_resource_bounds` the check at line 71 is:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { … });
}
```

`resource_bounds` is `AllResourceBounds`, whose `l2_gas` field defaults to `ResourceBounds { max_amount: 0, max_price_per_unit: 0 }` when the sender only specifies L1 or L1-data-gas bounds. Because `0 < 8_000_000_000` is always true, every such transaction is unconditionally rejected before it ever reaches the mempool.

The production default is confirmed in `StatelessTransactionValidatorConfig::default()`:

```rust
min_gas_price: 8_000_000_000,
```

and in `config_schema.json`:

```json
"gateway_config.static_config.stateless_tx_validator_config.min_gas_price": {
    "value": 8000000000
}
```

The test suite defines `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` with `min_gas_price: 0`, so the three positive-flow test cases `valid_l1_gas`, `valid_l1_data_gas`, and `valid_l1_and_l2_gas` all pass — but they do not exercise the production code path. The test `max_l2_gas_price_below_min` (which uses `DEFAULT_VALIDATOR_CONFIG` with the real 8 Gwei floor) only tests a transaction that *does* set a non-zero L2 gas amount, so the zero-L2-gas scenario is never tested against the production config.

The structural analog to the external report is exact: just as `_doMixSwap` calls `approve()` on every token address without first checking whether the address is the ETH placeholder (which has no contract code), `validate_resource_bounds` applies the L2 gas price floor to every transaction without first checking whether the transaction has any L2 gas bounds at all.

### Impact Explanation

Every V3 transaction that legitimately carries only L1 or L1-data-gas bounds is permanently rejected at the gateway admission layer in production. No such transaction can ever reach the mempool or be sequenced. This matches the **High** impact category: *"Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

### Likelihood Explanation

The production config is deployed with `min_gas_price = 8_000_000_000`. Any user or SDK that constructs a V3 transaction with `AllResourceBounds { l1_gas: <non-zero>, l2_gas: Default::default(), … }` — a pattern explicitly documented as valid by the `valid_l1_gas` test — will have their transaction rejected. The trigger requires no privilege and no special state.

### Recommendation

Guard the L2 gas price check so it is only applied when the sender has actually expressed a non-zero L2 gas amount:

```rust
// Only enforce the L2 gas price floor when the sender is actually
// bidding for L2 gas. Transactions that carry only L1 / L1-data-gas
// bounds have l2_gas.max_price_per_unit == 0 by construction and
// must not be rejected on that basis.
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
```

The corresponding unit tests (`valid_l1_gas`, `valid_l1_data_gas`) should be updated to use `DEFAULT_VALIDATOR_CONFIG` (with the real 8 Gwei floor) rather than the testing override, so the fix is regression-tested against production values.

### Proof of Concept

1. Construct a V3 `RpcTransaction` (Invoke, Declare, or DeployAccount) with:
   ```
   resource_bounds = AllResourceBounds {
       l1_gas: ResourceBounds { max_amount: 1000, max_price_per_unit: 10_000_000_000 },
       l2_gas: ResourceBounds::default(),   // max_price_per_unit = 0
       l1_data_gas: ResourceBounds::default(),
   }
   ```
2. Submit to the gateway running with the production `StatelessTransactionValidatorConfig` (`min_gas_price = 8_000_000_000`, `validate_resource_bounds = true`).
3. `validate_resource_bounds` evaluates `0 < 8_000_000_000 → true` and returns:
   ```
   Err(MaxGasPriceTooLow { gas_price: GasPrice(0), min_gas_price: 8_000_000_000 })
   ```
4. The transaction is rejected before reaching the mempool, despite having a valid and sufficient L1 gas bid.

The exact code path is: [1](#0-0) 

Production default confirming `min_gas_price = 8_000_000_000`: [2](#0-1) 

Test config that masks the bug with `min_gas_price = 0`: [3](#0-2) 

Positive-flow test cases that pass only because `min_gas_price = 0`: [4](#0-3)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L54-67)
```rust
static DEFAULT_VALIDATOR_CONFIG_FOR_TESTING: LazyLock<StatelessTransactionValidatorConfig> =
    LazyLock::new(|| StatelessTransactionValidatorConfig {
        validate_resource_bounds: false,
        min_gas_price: 0,
        max_l2_gas_amount: 1_000_000_000,
        max_calldata_length: 10,
        max_signature_length: 1,
        max_proof_size: 10,
        max_contract_bytecode_size: 100_000,
        max_contract_class_object_size: 100_000,
        min_sierra_version: *MIN_SIERRA_VERSION,
        max_sierra_version: *MAX_SIERRA_VERSION,
        allow_client_side_proving: true,
    });
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L69-122)
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
#[case::valid_l2_gas(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: NON_EMPTY_RESOURCE_BOUNDS,
            ..Default::default()
        },
        ..Default::default()
    }
)]
#[case::valid_l1_and_l2_gas(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l1_gas: NON_EMPTY_RESOURCE_BOUNDS,
            l2_gas: NON_EMPTY_RESOURCE_BOUNDS,
            ..Default::default()
        },
        ..Default::default()
    }
)]
#[case::valid_l1_data_gas(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l1_data_gas: NON_EMPTY_RESOURCE_BOUNDS,
            ..Default::default()
        },
        ..Default::default()
    }
)]
```
