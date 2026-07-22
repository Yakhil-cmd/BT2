### Title
Gateway Stateless Validator Unconditionally Checks `l2_gas.max_price_per_unit` Against `min_gas_price` Even When `l2_gas.max_amount` Is Zero, Incorrectly Rejecting Valid Transactions — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary
`StatelessTransactionValidator::validate_resource_bounds` applies the `min_gas_price` check to `l2_gas.max_price_per_unit` for every transaction regardless of whether `l2_gas.max_amount > 0`. When `l2_gas.max_amount = 0`, the price per unit is economically irrelevant (total L2 gas cost = `0 × price = 0`). In production where `min_gas_price > 0`, any transaction that legitimately allocates zero L2 gas is incorrectly rejected at the gateway admission stage.

### Finding Description
In `validate_resource_bounds`, lines 71–75:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
``` [1](#0-0) 

This fires unconditionally for all transaction types (Declare, DeployAccount, Invoke) without first verifying that `l2_gas.max_amount > 0`. When `l2_gas.max_amount = 0`, the price field is irrelevant: the total L2 gas cost is zero regardless of the price value. Yet the check still rejects the transaction if `l2_gas.max_price_per_unit < min_gas_price`.

The production `min_gas_price` is non-zero. The negative test `max_l2_gas_price_below_min` uses `DEFAULT_VALIDATOR_CONFIG.min_gas_price - 1`, confirming `min_gas_price ≥ 1` in the non-testing config. [2](#0-1) 

The testing config uses `min_gas_price = 0` specifically to allow the `valid_l1_gas` test case — which submits a transaction with `l2_gas = Default::default()` (`max_amount = 0, max_price_per_unit = 0`) — to pass. [3](#0-2) 

This masking means the bug is invisible in the test suite but active in production. By contrast, the sibling `max_l2_gas_amount` check (lines 79–85) is correctly conditioned on transaction type (skipped for Declare), but neither check is conditioned on `l2_gas.max_amount > 0`. [4](#0-3) 

The full `validate_resource_bounds` function is the sole stateless admission gate for resource bounds: [5](#0-4) 

### Impact Explanation
A valid V3 transaction that allocates zero L2 gas (`l2_gas.max_amount = 0, max_price_per_unit = 0`) is permanently rejected at the stateless gateway admission stage with `MaxGasPriceTooLow`. The transaction never reaches the mempool or blockifier. This matches the allowed impact: **High — Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

### Likelihood Explanation
Any user or wallet that constructs a V3 transaction with only L1 gas bounds (setting `l2_gas` to its zero default) will be rejected in production. The `valid_l1_gas` test case explicitly models this as a valid transaction. The trigger requires no special privileges — any unprivileged user submitting such a transaction hits the bug. The only reason the existing test suite does not catch this is that `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` sets `min_gas_price = 0`.

### Recommendation
Guard the `min_gas_price` check with a non-zero amount condition:

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

Add a corresponding test with `min_gas_price = 1` and `l2_gas.max_amount = 0` to confirm the fix.

### Proof of Concept
1. Configure `StatelessTransactionValidatorConfig` with `validate_resource_bounds: true` and `min_gas_price = 1` (production default).
2. Construct a V3 Invoke transaction with:
   - `l1_gas = { max_amount: 1000, max_price_per_unit: 1 }` (non-zero, valid)
   - `l2_gas = { max_amount: 0, max_price_per_unit: 0 }` (zero L2 gas — the `valid_l1_gas` test case)
   - `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }`
3. Call `StatelessTransactionValidator::validate(&tx)`.
4. The validator returns `Err(MaxGasPriceTooLow { gas_price: 0, min_gas_price: 1 })` even though the transaction is valid.

The `valid_l1_gas` test case already demonstrates the valid scenario but uses `min_gas_price = 0` in the test config, masking the production failure. [5](#0-4) [3](#0-2) [2](#0-1)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L213-228)
```rust
#[case::max_l2_gas_price_below_min(
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_price_per_unit: GasPrice(DEFAULT_VALIDATOR_CONFIG.min_gas_price - 1),
                ..NON_EMPTY_RESOURCE_BOUNDS
            },
            ..Default::default()
        },
        ..Default::default()
    },
    StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: GasPrice(DEFAULT_VALIDATOR_CONFIG.min_gas_price - 1),
        min_gas_price: DEFAULT_VALIDATOR_CONFIG.min_gas_price
    },
)]
```
