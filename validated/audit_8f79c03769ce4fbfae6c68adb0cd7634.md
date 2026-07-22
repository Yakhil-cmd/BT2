### Title
Stateless gateway unconditionally checks `l2_gas.max_price_per_unit >= min_gas_price` for all transactions, permanently rejecting valid L1-only-resource-bound transactions in production - (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies the `min_gas_price` floor check exclusively against `l2_gas.max_price_per_unit`, regardless of whether the transaction carries any L2 gas at all. In production the floor is `8_000_000_000`. A transaction that legitimately carries only L1 gas bounds (L2 gas price = 0) therefore always fails the check and is permanently rejected at the gateway admission layer, even though the same transaction type is explicitly expected to pass in the test suite.

### Finding Description

`validate_resource_bounds` in `stateless_transaction_validator.rs` line 71:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
``` [1](#0-0) 

`resource_bounds` is always `AllResourceBounds` (the RPC wire type). When a sender sets only `l1_gas` and leaves `l2_gas` at its zero default, `l2_gas.max_price_per_unit` is `GasPrice(0)`. The comparison `0 < 8_000_000_000` is always true, so the transaction is unconditionally rejected with `MaxGasPriceTooLow`.

The production default is `min_gas_price: 8_000_000_000`: [2](#0-1) 

confirmed by the deployed gateway config: [3](#0-2) 

The test suite masks the bug by using `min_gas_price: 0` in `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING`: [4](#0-3) 

The `valid_l1_gas` positive test case explicitly asserts that a transaction with only L1 gas bounds must pass: [5](#0-4) 

That test inherits `min_gas_price: 0`, so it passes in CI but would fail under the production value of `8_000_000_000`.

The stateful validator compounds the asymmetry: it skips the gas-price threshold check entirely for `ValidResourceBounds::L1Gas` transactions with the comment "No validation required for legacy transactions": [6](#0-5) 

So the two validators are inconsistent: the stateless layer over-rejects L1-only transactions (L2 price = 0 < floor), while the stateful layer under-checks them (no price floor at all).

### Impact Explanation

**High — Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

Any user or protocol component that submits a V3 transaction with only `l1_gas` resource bounds (a supported and tested transaction shape) will receive a permanent `MaxGasPriceTooLow` rejection from the production gateway. The transaction never reaches the mempool or blockifier. The exact wrong value is `gas_price: GasPrice(0)` vs `min_gas_price: 8_000_000_000`.

### Likelihood Explanation

Medium. The affected transaction shape (`AllResourceBounds` with non-zero `l1_gas` and zero `l2_gas`/`l1_data_gas`) is a first-class supported type — the test suite has a dedicated positive case for it. Any wallet or SDK that constructs L1-only V3 transactions will hit this rejection on every submission against a production node.

### Recommendation

The `min_gas_price` floor should be applied only to the gas dimension(s) the transaction actually uses. The simplest correct fix is to skip the L2 price check when `l2_gas.max_price_per_unit` is zero and the transaction has non-zero L1 or L1-data gas bounds:

```rust
// Only enforce the L2 gas price floor when the transaction actually bids L2 gas.
if resource_bounds.l2_gas.max_price_per_unit.0 != 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

A more complete fix would apply the floor to whichever gas dimension(s) are non-zero, mirroring the zero-bounds check already present: [7](#0-6) 

The TODO comment in `StatelessTransactionValidatorConfig` already acknowledges that `min_gas_price` should eventually be sourced from versioned constants: [8](#0-7) 

That migration should also fix the per-resource-type scoping.

### Proof of Concept

1. Build a V3 invoke transaction with:
   ```
   resource_bounds = AllResourceBounds {
       l1_gas: ResourceBounds { max_amount: 1000, max_price_per_unit: 1_000_000_000 },
       l2_gas: ResourceBounds::default(),   // price = 0
       l1_data_gas: ResourceBounds::default(),
   }
   ```
2. Submit to a gateway running with the production config (`min_gas_price = 8_000_000_000`, `validate_resource_bounds = true`).
3. `validate_resource_bounds` evaluates `0 < 8_000_000_000 → true` and returns `Err(MaxGasPriceTooLow { gas_price: GasPrice(0), min_gas_price: 8_000_000_000 })`.
4. The transaction is rejected at the stateless gateway layer; it never reaches the mempool.
5. The same transaction submitted to a test node with `min_gas_price = 0` passes — confirming the production-only nature of the rejection.

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L64-69)
```rust
        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L71-76)
```rust
        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }
```

**File:** crates/apollo_gateway_config/src/config.rs (L170-172)
```rust
    // TODO(AlonH): Remove the `min_gas_price` field from this struct and use the one from the
    // versioned constants.
    pub min_gas_price: u128,
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L31-31)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": 8000000000,
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L385-388)
```rust
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
        }
```
