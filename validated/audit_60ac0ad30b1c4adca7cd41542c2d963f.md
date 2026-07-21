### Title
Declare V3 Transactions Bypass `max_l2_gas_amount` Gateway Admission Check — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` unconditionally skips the `max_l2_gas_amount` upper-bound check for `RpcTransaction::Declare`. An unprivileged attacker can submit a Declare V3 transaction with `l2_gas.max_amount` exceeding the operator-configured limit and have it admitted through the gateway and into the mempool, while an identical Invoke or DeployAccount transaction with the same gas amount would be rejected.

### Finding Description

In `validate_resource_bounds`, the check that enforces `resource_bounds.l2_gas.max_amount.0 <= self.config.max_l2_gas_amount` is guarded by an `else if` that is only reached when the transaction is **not** a `Declare`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // empty — no check performed
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The default `max_l2_gas_amount` is `1_210_000_000`: [2](#0-1) 

The stateful validator's `validate_resource_bounds` only checks `l2_gas.max_price_per_unit` against the previous block's gas price threshold — it does **not** check `max_amount` at all: [3](#0-2) 

The blockifier's pre-validation (`check_fee_bounds` / `verify_can_pay_committed_bounds`) only rejects a transaction if `max_amount * max_price_per_unit` exceeds the account's actual balance. For any `max_amount` value where the account can cover the resulting fee, the transaction passes all downstream checks and is admitted.

The bypass is explicitly tested and documented as intentional (for now) in the test suite: [4](#0-3) 

And the `test_invalid_max_l2_gas_amount` test deliberately excludes `TransactionType::Declare` from the types it checks: [5](#0-4) 

### Impact Explanation

The concrete corrupted admission value is: a Declare V3 transaction with `l2_gas.max_amount > max_l2_gas_amount` is admitted to the mempool when the operator's configuration mandates it should be rejected. This is an asymmetric admission policy — the same resource-bound value that causes rejection for Invoke/DeployAccount is silently accepted for Declare. Any account with sufficient balance to cover `max_amount * max_price_per_unit` can exploit this.

### Likelihood Explanation

Trivially triggerable by any unprivileged user who can submit transactions to the gateway RPC. No special privileges, keys, or state are required beyond having a funded account. The bypass is unconditional for all Declare V3 transactions.

### Recommendation

Remove the `Declare` exemption and apply the same `max_l2_gas_amount` upper-bound check to all transaction types:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If a higher limit is intentionally desired for declares (e.g., because class compilation is more gas-intensive), introduce a separate `max_l2_gas_amount_declare` config field rather than removing the check entirely.

### Proof of Concept

```rust
#[test]
fn declare_bypasses_max_l2_gas_amount() {
    use starknet_api::transaction::fields::{GasAmount, GasPrice, ResourceBounds, AllResourceBounds};
    use apollo_gateway_config::config::StatelessTransactionValidatorConfig;
    use crate::stateless_transaction_validator::StatelessTransactionValidator;

    let config = StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 100,
        min_gas_price: 1,
        ..StatelessTransactionValidatorConfig::default()
    };
    let validator = StatelessTransactionValidator { config };

    // Build a Declare V3 tx with l2_gas.max_amount = u64::MAX >> well above limit of 100
    let resource_bounds = AllResourceBounds {
        l2_gas: ResourceBounds {
            max_amount: GasAmount(u64::MAX),
            max_price_per_unit: GasPrice(1),
        },
        ..Default::default()
    };
    let tx = rpc_declare_tx_for_testing(resource_bounds); // helper that builds RpcTransaction::Declare

    // Asserts Ok(()) — the declare is admitted despite max_amount >> max_l2_gas_amount
    assert_eq!(validator.validate(&tx), Ok(()));
}
```

This mirrors the existing `valid_l2_gas_amount_on_declare` test case already present in the test suite, which passes `GasAmount(200)` against a limit of `100` and asserts `Ok(())`. [4](#0-3)

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

**File:** crates/apollo_gateway_config/src/config.rs (L193-193)
```rust
            max_l2_gas_amount: 1_210_000_000,
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L260-263)
```rust
fn test_invalid_max_l2_gas_amount(
    #[case] rpc_tx_args: RpcTransactionArgs,
    #[case] expected_error: StatelessTransactionValidatorError,
    #[values(TransactionType::DeployAccount, TransactionType::Invoke)] tx_type: TransactionType,
```
