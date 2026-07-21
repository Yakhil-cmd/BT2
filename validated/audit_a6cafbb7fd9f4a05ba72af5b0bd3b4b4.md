### Title
Unconditional `l2_gas.max_price_per_unit < min_gas_price` Check Rejects Valid Transactions When `l2_gas.max_amount == 0` - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies a `min_gas_price` floor check on `l2_gas.max_price_per_unit` unconditionally, even when `l2_gas.max_amount == 0`. When the amount is zero the price is irrelevant (0 × price = 0 cost), so the check is unnecessary and causes the gateway to reject transactions that carry non-zero `l1_gas` or `l1_data_gas` bounds but set `l2_gas` to all-zeros. The same structural defect is present in the stateful validator's `validate_tx_l2_gas_price_within_threshold`.

### Finding Description

`validate_resource_bounds` in the stateless validator performs two sequential checks:

1. **`ZeroResourceBounds`** – rejects only when `max_possible_fee(Tip::ZERO) == 0`, i.e., when *all three* resource bounds are zero.
2. **`min_gas_price`** – unconditionally rejects when `l2_gas.max_price_per_unit < config.min_gas_price`. [1](#0-0) 

A transaction with `l1_gas.max_amount > 0` (or `l1_data_gas.max_amount > 0`) and `l2_gas = {max_amount: 0, max_price_per_unit: 0}` passes check 1 (total fee > 0) but fails check 2 (`0 < 8_000_000_000` in production). The l2_gas price is economically irrelevant when the amount is zero, so the rejection is spurious.

The production configuration confirms `min_gas_price = 8_000_000_000` and `validate_resource_bounds = true`: [2](#0-1) 

The test suite masks the bug by setting `min_gas_price: 0` in `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING`, which makes `0 < 0` false and silently passes all the `valid_l1_gas` / `valid_l1_data_gas` positive-flow cases: [3](#0-2) 

The stateful validator's `validate_tx_l2_gas_price_within_threshold` has the identical pattern – it checks `tx_l2_gas_price.0 < threshold` for every `AllResources` transaction without first verifying `l2_gas.max_amount > 0`: [4](#0-3) 

### Impact Explanation

The gateway is the first admission gate. A transaction that passes the `ZeroResourceBounds` check (non-zero l1_gas or l1_data_gas) but carries `l2_gas.max_price_per_unit = 0` is rejected with `MaxGasPriceTooLow` before it ever reaches the mempool or blockifier. This is a **High** impact: the gateway/mempool admission path rejects transactions that are structurally valid under the protocol's own `ZeroResourceBounds` invariant.

### Likelihood Explanation

Any unprivileged user can trigger this by submitting a V3 `AllResources` transaction with:
- `l1_gas.max_amount > 0`, `l1_gas.max_price_per_unit > 0`
- `l2_gas.max_amount = 0`, `l2_gas.max_price_per_unit = 0`
- `l1_data_gas` at any value

No special privilege, no prior state, no coordination required. The trigger is a single RPC call to the HTTP gateway.

### Recommendation

Guard the `min_gas_price` check with a non-zero amount condition in both validators:

**Stateless validator** (`crates/apollo_gateway/src/stateless_transaction_validator.rs`):
```rust
// Only enforce the price floor when the sender actually allocates L2 gas.
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

**Stateful validator** (`crates/apollo_gateway/src/stateful_transaction_validator.rs`):
```rust
ValidResourceBounds::AllResources(tx_resource_bounds) => {
    if tx_resource_bounds.l2_gas.max_amount.0 > 0 {
        // existing threshold check
    }
}
```

### Proof of Concept

Submit the following V3 invoke transaction to the gateway (pseudocode):

```
RpcInvokeTransactionV3 {
    resource_bounds: AllResourceBounds {
        l1_gas:      { max_amount: 1,  max_price_per_unit: 1 },   // non-zero → passes ZeroResourceBounds
        l2_gas:      { max_amount: 0,  max_price_per_unit: 0 },   // zero amount, zero price
        l1_data_gas: { max_amount: 0,  max_price_per_unit: 0 },
    },
    ...
}
```

**Step 1** – `ZeroResourceBounds` check: `max_possible_fee(Tip::ZERO) = 1 * 1 = 1 ≠ 0` → **passes**.

**Step 2** – `min_gas_price` check: `0 < 8_000_000_000` → **`MaxGasPriceTooLow` error returned**, transaction rejected.

The transaction is rejected for a reason that is economically meaningless (the l2_gas price is irrelevant when the l2_gas amount is zero), matching the external bug pattern where an unnecessary sub-operation guard (`payInAmount > 0`) causes a valid outer call to revert. [5](#0-4)

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

**File:** crates/apollo_node/resources/config_schema.json (L3202-3226)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": {
    "description": "Minimum gas price for transactions.",
    "privacy": "Public",
    "value": 8000000000
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.major": {
    "description": "The major version of the configuration.",
    "privacy": "Public",
    "value": 1
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.minor": {
    "description": "The minor version of the configuration.",
    "privacy": "Public",
    "value": 1
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.patch": {
    "description": "The patch version of the configuration.",
    "privacy": "Public",
    "value": 0
  },
  "gateway_config.static_config.stateless_tx_validator_config.validate_resource_bounds": {
    "description": "If true, ensures that at least one resource bound (L1, L2, or L1 data) is greater than zero.",
    "pointer_target": "validate_resource_bounds",
    "privacy": "Public"
  },
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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
