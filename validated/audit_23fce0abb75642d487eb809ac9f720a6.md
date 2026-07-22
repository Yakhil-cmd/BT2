The code gap is confirmed and real. Let me verify the downstream execution path to assess the full impact.

The code gap is fully confirmed. Here is the complete analysis:

---

### Title
Declare Transaction `l2_gas.max_amount` Bypass in `StatelessTransactionValidator::validate_resource_bounds` — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `max_l2_gas_amount` upper-bound check for `RpcTransaction::Declare`, while enforcing it for Invoke and DeployAccount. An unprivileged user can submit a `RpcDeclareTransactionV3` with `l2_gas.max_amount = u64::MAX` and it will pass all gateway validation layers, entering the mempool in violation of the operator-configured admission policy.

### Finding Description

In `crates/apollo_gateway/src/stateless_transaction_validator.rs`, the `validate_resource_bounds` method contains:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The `Declare` arm is an empty block — it falls through to `Ok(())` unconditionally, regardless of `l2_gas.max_amount`. The production `max_l2_gas_amount` is configured at `1,210,000,000`. [2](#0-1) 

The existing test `valid_l2_gas_amount_on_declare` explicitly asserts this bypass is the current behavior — a Declare with `max_amount=200` passes when `max_l2_gas_amount=100`: [3](#0-2) 

The stateful validator's `validate_resource_bounds` only checks `l2_gas.max_price_per_unit` against a threshold — it does not check `max_amount` at all: [4](#0-3) 

So the full gateway path (stateless → stateful) admits the Declare unconditionally on the `max_amount` dimension.

### Impact Explanation

**Concrete corrupted admission value**: A `RpcDeclareTransactionV3` with `l2_gas.max_amount = u64::MAX` (or any value exceeding `max_l2_gas_amount`) is admitted by the gateway and inserted into the mempool, when the operator's policy requires it to be rejected.

**Downstream execution path**: In `perform_pre_validation_stage`, `verify_can_pay_committed_bounds` computes `max_possible_fee` using saturating arithmetic (`u64::MAX * price`). If the product exceeds the account's STRK balance, the transaction is rejected at sequencing time — but only after it has already occupied mempool space. If the attacker controls an account with sufficient balance (or sets `max_price_per_unit` to a value where `u64::MAX * price` fits within their balance), the transaction executes normally; actual fees are based on actual gas consumed, not `max_amount`. [5](#0-4) [6](#0-5) 

The OS-level `get_initial_user_gas_bound` uses `l2_gas.max_amount` as the initial gas for the `__validate_declare__` entry point, but it is capped by `VALIDATE_MAX_SIERRA_GAS` via `cap_remaining_gas`, so execution gas is bounded regardless: [7](#0-6) 

### Likelihood Explanation

Trivially exploitable by any unprivileged user who can submit transactions to the gateway. No special privileges, keys, or state are required. The attacker only needs to construct a valid `RpcDeclareTransactionV3` with an oversized `l2_gas.max_amount` field.

### Recommendation

Apply the same `max_l2_gas_amount` check to Declare transactions. Remove the empty `if let RpcTransaction::Declare(_) = tx {}` branch and let the existing `else if` apply uniformly:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Also update `test_invalid_max_l2_gas_amount` to include `TransactionType::Declare` in its `#[values(...)]` list.

### Proof of Concept

```rust
#[test]
fn declare_bypasses_max_l2_gas_amount() {
    let config = StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 1_000,
        min_gas_price: 1,
        // ... other fields
    };
    let validator = StatelessTransactionValidator { config };

    // Declare with l2_gas.max_amount = u64::MAX — should be rejected, is admitted
    let declare_tx = rpc_tx_for_testing(TransactionType::Declare, RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(u64::MAX),
                max_price_per_unit: GasPrice(1),
            },
            ..Default::default()
        },
        ..Default::default()
    });
    assert_matches!(validator.validate(&declare_tx), Ok(())); // passes — bypass confirmed

    // Same max_amount on Invoke — correctly rejected
    let invoke_tx = rpc_tx_for_testing(TransactionType::Invoke, RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(u64::MAX),
                max_price_per_unit: GasPrice(1),
            },
            ..Default::default()
        },
        ..Default::default()
    });
    assert_matches!(
        validator.validate(&invoke_tx),
        Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { .. })
    );
}
```

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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L363-367)
```rust
        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-180)
```rust
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = tx_context.max_possible_fee();
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/transaction_impls.cairo (L799-801)
```text
    let remaining_gas = get_initial_user_gas_bound(common_tx_fields=common_tx_fields);
    with remaining_gas {
        cap_remaining_gas(max_gas=VALIDATE_MAX_SIERRA_GAS);
```
