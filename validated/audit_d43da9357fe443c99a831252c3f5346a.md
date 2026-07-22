Looking at the `validate_resource_bounds` function in the stateless validator, I can see a clear analog to the HoneyFactory basket mode bug. Let me verify the exact behavior.

### Title
Gateway Stateless Validator Unconditionally Rejects Valid Transactions with Zero L2 Gas Amount Due to Missing Zero-Amount Guard in `validate_resource_bounds` — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies the `min_gas_price` check on `l2_gas.max_price_per_unit` unconditionally for every `AllResources` transaction, even when `l2_gas.max_amount == 0`. With the production default `min_gas_price = 8_000_000_000`, any transaction that carries a non-zero L1 gas fee but sets L2 gas to zero is rejected at the gateway admission stage with `MaxGasPriceTooLow`, despite being a structurally valid transaction.

---

### Finding Description

In `validate_resource_bounds` the logic is:

```rust
// line 66-69: passes if any resource contributes a non-zero fee
if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0) {
    return Err(ZeroResourceBounds { resource_bounds });
}

// line 71-76: UNCONDITIONAL — no guard for l2_gas.max_amount == 0
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
``` [1](#0-0) 

The production default is `min_gas_price: 8_000_000_000`. [2](#0-1) 

Consider a transaction with:
- `l1_gas = { max_amount: 1000, max_price_per_unit: 10_000_000_000 }` → contributes `10^13` to `max_possible_fee`
- `l2_gas = { max_amount: 0, max_price_per_unit: 0 }` → zero L2 gas, legitimately unused
- `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }`

Step 1 (line 66): `max_possible_fee = 10^13 ≠ 0` → **passes**.
Step 2 (line 71): `l2_gas.max_price_per_unit.0 = 0 < 8_000_000_000` → **rejected** with `MaxGasPriceTooLow`.

The check does not ask whether `l2_gas.max_amount > 0` before enforcing a minimum price on that resource. This is structurally identical to the HoneyFactory basket-mode bug: a condition check iterates over (or reads) all registered resource slots without excluding zero-quantity ones, producing a wrong admission decision.

The test suite confirms the intent: `test_positive_flow::valid_l1_gas` explicitly asserts `Ok(())` for an `AllResources` transaction with only `l1_gas` non-zero. [3](#0-2) 

That test passes only because `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` sets `min_gas_price: 0`. [4](#0-3) 

Under the production config (`min_gas_price: 8_000_000_000`) the identical transaction is rejected. No existing guard preserves the invariant.

---

### Impact Explanation

**High. Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

Any user who submits a V3 `AllResources` transaction that intentionally or incidentally carries `l2_gas.max_amount = 0` with `l2_gas.max_price_per_unit = 0` (while funding the fee entirely through L1 gas) will receive a `MaxGasPriceTooLow` rejection from the production gateway. The transaction never reaches the mempool. The error message is misleading — it reports a price violation on a resource the sender is not using.

---

### Likelihood Explanation

Any unprivileged user can trigger this by submitting a standard V3 invoke, declare, or deploy-account transaction with `l2_gas` zeroed out. No special account, privileged role, or race condition is required. The trigger is a single RPC call to `add_transaction`.

---

### Recommendation

Guard the `min_gas_price` check (and the symmetric `max_l2_gas_amount` check) with a zero-amount test:

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

This mirrors the correct pattern already used in `validate_tx_l2_gas_price_within_threshold` in the stateful validator, which only fires for `ValidResourceBounds::AllResources` and implicitly relies on the caller to have already confirmed the resource is in use. [5](#0-4) 

---

### Proof of Concept

Submit the following V3 invoke transaction to the production gateway (with `validate_resource_bounds: true`, `min_gas_price: 8_000_000_000`):

```json
{
  "type": "INVOKE",
  "version": "0x3",
  "sender_address": "<valid_deployed_account>",
  "calldata": [...],
  "resource_bounds": {
    "l1_gas":      { "max_amount": "0x3e8", "max_price_per_unit": "0x2540be400" },
    "l2_gas":      { "max_amount": "0x0",   "max_price_per_unit": "0x0" },
    "l1_data_gas": { "max_amount": "0x0",   "max_price_per_unit": "0x0" }
  },
  "tip": "0x0",
  "nonce": "0x...",
  "nonce_data_availability_mode": "L1",
  "fee_data_availability_mode": "L1",
  "paymaster_data": [],
  "account_deployment_data": [],
  "signature": [...]
}
```

**Expected (correct) result:** Admitted to mempool — `max_possible_fee = 1000 × 10_000_000_000 = 10^13 > 0`.

**Actual result:** Rejected at stateless validation with:
```
MaxGasPriceTooLow { gas_price: GasPrice(0), min_gas_price: 8000000000 }
```

The root cause is the unconditional check at line 71 of `crates/apollo_gateway/src/stateless_transaction_validator.rs`, which reads `l2_gas.max_price_per_unit` without first confirming `l2_gas.max_amount > 0`. [6](#0-5)

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

**File:** crates/apollo_gateway_config/src/config.rs (L191-192)
```rust
            validate_resource_bounds: true,
            min_gas_price: 8_000_000_000,
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L70-82)
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L364-390)
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
        Ok(())
    }
```
