### Title
`validate_resource_bounds` unconditionally applies `min_gas_price` to `l2_gas.max_price_per_unit`, causing gateway to reject valid L1-only transactions - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` checks `resource_bounds.l2_gas.max_price_per_unit < min_gas_price` for every transaction, regardless of whether the transaction uses L2 gas at all. In production, `min_gas_price` defaults to `8_000_000_000`. Any transaction that sets only L1 gas or L1 data gas bounds (leaving `l2_gas.max_price_per_unit = 0`) will always fail this check with `MaxGasPriceTooLow`, even though the transaction is economically valid and would be accepted by the blockifier.

### Finding Description

In `validate_resource_bounds`:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator.rs, lines 56-88
fn validate_resource_bounds(
    &self,
    tx: &RpcTransaction,
) -> StatelessTransactionValidatorResult<()> {
    if !self.config.validate_resource_bounds {
        return Ok(());
    }

    let resource_bounds = *tx.resource_bounds();
    if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0) {
        return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
    }

    if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {  // ← BUG
        return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
    }
    ...
}
```

The `ZeroResourceBounds` guard only rejects transactions where **all** resource bounds are zero. A transaction with `l1_gas = {max_amount: 1, max_price_per_unit: 1}` and `l2_gas = default (0, 0)` passes the first check (fee > 0) but then hits `0 < 8_000_000_000 = true` and is rejected.

The production default config sets `min_gas_price: 8_000_000_000`:

```rust
// crates/apollo_gateway_config/src/config.rs, line 192
min_gas_price: 8_000_000_000,
```

The test suite masks this by using `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` with `min_gas_price: 0`:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator_test.rs, lines 54-67
static DEFAULT_VALIDATOR_CONFIG_FOR_TESTING: LazyLock<StatelessTransactionValidatorConfig> =
    LazyLock::new(|| StatelessTransactionValidatorConfig {
        validate_resource_bounds: false,
        min_gas_price: 0,   // ← hides the production bug
        ...
    });
```

The positive test cases `valid_l1_gas` and `valid_l1_data_gas` both spread `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` (with `min_gas_price: 0`) and override only `validate_resource_bounds: true`. They pass in CI but would fail against the production default.

Real on-chain transactions confirm `l2_gas.max_price_per_unit = 0x0` is a legitimate pattern (e.g., `crates/apollo_starknet_client/resources/reader/block_post_0_14_2.json` lines 336-338).

### Impact Explanation

**High — Gateway/RPC admission rejects valid transactions before sequencing.**

Any user submitting a V3 transaction that only allocates L1 gas or L1 data gas (with `l2_gas.max_price_per_unit = 0`) will receive a `MaxGasPriceTooLow` error from the gateway and the transaction will never reach the mempool or blockifier. The blockifier itself would accept such a transaction; the rejection is a gateway-layer false positive.

### Likelihood Explanation

High. The condition `l2_gas.max_price_per_unit = 0` is the natural default for any transaction that does not intend to pay for L2 gas. The `AllResourceBounds::default()` struct produces exactly this value. Any client that constructs a transaction with only L1 gas bounds will hit this rejection unconditionally in production.

### Recommendation

Gate the `min_gas_price` check on whether the transaction actually uses L2 gas:

```rust
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
```

Additionally, add a test case that uses the **production** `DEFAULT_VALIDATOR_CONFIG` (not the testing one with `min_gas_price: 0`) to cover the `valid_l1_gas` and `valid_l1_data_gas` scenarios.

### Proof of Concept

1. Construct a V3 invoke transaction with:
   - `l1_gas = { max_amount: 1, max_price_per_unit: 1 }`
   - `l2_gas = { max_amount: 0, max_price_per_unit: 0 }` (default)
   - `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }` (default)
2. Submit to a gateway running with the production `StatelessTransactionValidatorConfig` (`min_gas_price: 8_000_000_000`, `validate_resource_bounds: true`).
3. The gateway returns `MaxGasPriceTooLow { gas_price: 0, min_gas_price: 8_000_000_000 }` and drops the transaction.
4. The same transaction submitted directly to the blockifier executes successfully.

The root cause is at: [1](#0-0) 

The production default that makes this always-fail for L1-only transactions: [2](#0-1) 

The test config that hides the bug by zeroing `min_gas_price`: [3](#0-2) 

The positive test cases that are only valid under the zeroed test config, not production: [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L71-76)
```rust
        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }
```

**File:** crates/apollo_gateway_config/src/config.rs (L192-193)
```rust
            min_gas_price: 8_000_000_000,
            max_l2_gas_amount: 1_210_000_000,
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L70-122)
```rust
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
