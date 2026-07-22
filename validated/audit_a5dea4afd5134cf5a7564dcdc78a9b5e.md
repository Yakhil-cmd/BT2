### Title
Gateway Stateless Validator Rejects Valid Transactions with Zero L2 Gas Amount Due to Unconditional Price Check - (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies the `l2_gas.max_price_per_unit >= min_gas_price` check unconditionally, even when `l2_gas.max_amount == 0`. In production, `min_gas_price` is `8_000_000_000`. Any transaction that carries non-zero L1 gas bounds (so it passes the "at least one resource is non-zero" guard) but leaves `l2_gas` at its zero default is rejected with `MaxGasPriceTooLow`, even though the L2 gas price is semantically irrelevant when no L2 gas is requested.

### Finding Description

`validate_resource_bounds` performs two sequential checks:

1. **Zero-resource guard** (line 66–69): rejects if `max_possible_fee(Tip::ZERO) == 0`. A transaction with only L1 gas bounds passes this guard because L1 gas contributes to the fee.

2. **L2 gas price floor** (line 71–76): rejects if `l2_gas.max_price_per_unit < min_gas_price`. This check is unconditional — it fires regardless of whether `l2_gas.max_amount` is zero. [1](#0-0) 

The production default sets `min_gas_price = 8_000_000_000`: [2](#0-1) 

Confirmed in the deployed app config: [3](#0-2) 

The existing positive-flow test `valid_l1_gas` exercises exactly this shape (non-zero L1 gas, zero L2 gas), but it uses `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` which hard-codes `min_gas_price: 0`, masking the production failure: [4](#0-3) 

The analog to the external bug is direct:

| External (Notional) | Sequencer |
|---|---|
| `vaultShares == 0` → redemption step should be skipped, but `_redeemStrategyTokens` is called and reverts with `ZeroPoolClaim` | `l2_gas.max_amount == 0` → L2 price check should be skipped, but `validate_resource_bounds` fires and returns `MaxGasPriceTooLow` |

### Impact Explanation

A well-formed transaction carrying sufficient L1 gas bounds to cover all fees, but with `l2_gas` left at its zero default (`max_amount = 0, max_price_per_unit = 0`), is permanently rejected at the gateway stateless path. The transaction never reaches the mempool or blockifier. This is a false-rejection at the admission layer.

Impact category: **High — Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

### Likelihood Explanation

Any client that constructs a V3 transaction using only L1 gas bounds (a supported and tested pattern, as shown by the `valid_l1_gas` test case) will hit this rejection in production. The `AllResourceBounds` default zero-initialises all three resource fields, so omitting L2 gas is the natural construction path. The bug is masked in the test suite only because the test config sets `min_gas_price: 0`.

### Recommendation

Guard the L2 gas price check with a non-zero amount condition, mirroring the pattern used for the `max_l2_gas_amount` upper-bound check immediately below it:

```rust
// Before (line 71):
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {

// After:
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
``` [5](#0-4) 

The `max_l2_gas_amount` upper-bound check already uses this conditional pattern (only applied when not a Declare tx): [6](#0-5) 

Additionally, add a test case to `test_positive_flow` that uses the production `DEFAULT_VALIDATOR_CONFIG` (with `min_gas_price = 8_000_000_000`) and `l1_gas`-only bounds, to prevent regression.

### Proof of Concept

Submit the following transaction to a gateway running with the default production config:

```
AllResourceBounds {
    l1_gas:      { max_amount: 1_000, max_price_per_unit: 10_000_000_000 },  // non-zero, covers fees
    l2_gas:      { max_amount: 0,     max_price_per_unit: 0 },               // default zero
    l1_data_gas: { max_amount: 0,     max_price_per_unit: 0 },               // default zero
}
```

**Step 1:** `max_possible_fee(Tip::ZERO)` = `1_000 × 10_000_000_000` = `10_000_000_000 > 0` → passes the zero-resource guard.

**Step 2:** `l2_gas.max_price_per_unit.0 = 0 < 8_000_000_000 = min_gas_price` → fires `MaxGasPriceTooLow`, transaction rejected.

The same transaction shape is accepted by the test suite only because `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` sets `min_gas_price: 0`: [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L64-76)
```rust
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
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L79-85)
```rust
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L31-31)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": 8000000000,
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L54-82)
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
