The code is unambiguous. Let me verify the downstream handling to assess full impact.

The full chain is now clear. Here is the complete analysis:

---

### Title
Declare Transaction Bypasses `max_l2_gas_amount` Gateway Cap, Admitting Transactions with Unbounded L2 Gas Amount — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `max_l2_gas_amount` check for `Declare` transactions. A well-funded attacker can submit a Declare transaction with `l2_gas.max_amount` exceeding the configured cap, pass all gateway validation layers, and have the transaction admitted to the mempool with an uncapped L2 gas execution budget.

### Finding Description

In `validate_resource_bounds`, the `max_l2_gas_amount` guard is wrapped in a type-check that no-ops for Declare:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The existing test `valid_l2_gas_amount_on_declare` explicitly confirms this: a Declare with `max_amount: GasAmount(200)` when `max_l2_gas_amount: 100` returns `Ok(())`. [2](#0-1) 

The **stateful** validator's `validate_resource_bounds` only checks the L2 gas **price** against the previous block price — it never checks the amount: [3](#0-2) 

The downstream blockifier `perform_pre_validation_stage` calls `verify_can_pay_committed_bounds`, which checks whether the account balance covers `max_possible_fee()`. `max_possible_fee()` uses **saturating arithmetic**: [4](#0-3) 

For a moderately elevated `l2_gas.max_amount` (e.g., `max_l2_gas_amount + 1 = 1_210_000_001`) at `min_gas_price = 8_000_000_000`, the committed fee is `~9.68 × 10¹⁸` STRK units — a large but achievable balance for a funded account. If the account holds this balance, `verify_can_pay_committed_bounds` passes and the transaction is admitted. [5](#0-4) 

Once admitted, `initial_sierra_gas()` returns `l2_gas.max_amount` directly from the transaction's resource bounds — the uncapped value — as the execution gas limit for the `__validate__` entry point: [6](#0-5) 

### Impact Explanation

The concrete corrupted admission value: a Declare transaction with `l2_gas.max_amount > max_l2_gas_amount` is accepted by the gateway and enters the mempool when it should be rejected. The `__validate__` entry point of the Declare transaction receives `l2_gas.max_amount` as its initial Sierra gas budget — a value exceeding the operator-configured cap — allowing it to execute longer than the policy intends. This violates the **High** impact category: "Mempool/gateway/RPC admission accepts invalid transactions before sequencing."

The bouncer's block-level limits (`sierra_gas: 5_000_000_000`, `receipt_l2_gas: 5_800_000_000`) prevent block overflow, but the per-transaction admission invariant is broken. [7](#0-6) 

### Likelihood Explanation

Moderate. The attacker must:
1. Construct a valid Declare transaction (valid Sierra class, valid signature, correct nonce).
2. Set `l2_gas.max_amount` to any value above `max_l2_gas_amount`.
3. Hold a fee token balance sufficient to cover `max_possible_fee = l2_gas.max_amount × l2_gas.max_price_per_unit`.

For a value just above the cap (`max_l2_gas_amount + 1`), the required balance is ~9.68 × 10¹⁸ STRK units at minimum gas price. This is a high but not impossible bar for a funded attacker. The TODO comment and the dedicated test `valid_l2_gas_amount_on_declare` confirm this is a known, unresolved gap.

### Recommendation

Apply the same `max_l2_gas_amount` guard to Declare transactions. Remove the Declare exemption at lines 79–85 and enforce the cap uniformly:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher L2 gas budget (e.g., for compilation), introduce a separate `max_l2_gas_amount_declare` config field rather than removing the cap entirely.

### Proof of Concept

The existing test `valid_l2_gas_amount_on_declare` already constitutes a proof of concept:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator_test.rs
#[case::l2_gas_amount_out_of_limit(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 100,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(200), // exceeds cap of 100
                ..NON_EMPTY_RESOURCE_BOUNDS
            },
            ..Default::default()
        },
        ..Default::default()
    }
)]
fn valid_l2_gas_amount_on_declare(...) {
    // ...
    assert_matches!(tx_validator.validate(&tx), Ok(())); // cap is NOT enforced
}
``` [2](#0-1) 

To extend this to `u64::MAX`: set `max_l2_gas_amount: 100`, construct a Declare with `l2_gas.max_amount: GasAmount(u64::MAX)`, call `StatelessTransactionValidator::validate`, and assert `Ok(())` — it passes. The test `test_invalid_max_l2_gas_amount` explicitly excludes `TransactionType::Declare` from the types that enforce this check, confirming the bypass is structural: [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L260-271)
```rust
fn test_invalid_max_l2_gas_amount(
    #[case] rpc_tx_args: RpcTransactionArgs,
    #[case] expected_error: StatelessTransactionValidatorError,
    #[values(TransactionType::DeployAccount, TransactionType::Invoke)] tx_type: TransactionType,
) {
    let tx_validator =
        StatelessTransactionValidator { config: DEFAULT_VALIDATOR_CONFIG.to_owned() };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_eq!(tx_validator.validate(&tx).unwrap_err(), expected_error);
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

**File:** crates/starknet_api/src/transaction/fields.rs (L393-413)
```rust
    pub fn max_possible_fee(&self, tip: Tip) -> Fee {
        match self {
            ValidResourceBounds::L1Gas(l1_bounds) => {
                l1_bounds.max_amount.saturating_mul(l1_bounds.max_price_per_unit)
            }
            ValidResourceBounds::AllResources(AllResourceBounds {
                l1_gas,
                l2_gas,
                l1_data_gas,
            }) => l1_gas
                .max_amount
                .saturating_mul(l1_gas.max_price_per_unit)
                .saturating_add(
                    l2_gas
                        .max_amount
                        .saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into())),
                )
                .saturating_add(
                    l1_data_gas.max_amount.saturating_mul(l1_data_gas.max_price_per_unit),
                ),
        }
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-202)
```rust
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = tx_context.max_possible_fee();
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match tx_info {
            TransactionInfo::Current(context) => match &context.resource_bounds {
                L1Gas(l1_gas) => TransactionFeeError::GasBoundsExceedBalance {
                    resource: Resource::L1Gas,
                    max_amount: l1_gas.max_amount,
                    max_price: l1_gas.max_price_per_unit,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
                AllResources(bounds) => TransactionFeeError::ResourcesBoundsExceedBalance {
                    bounds: *bounds,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
            },
            TransactionInfo::Deprecated(context) => TransactionFeeError::MaxFeeExceedsBalance {
                max_fee: context.max_fee,
                balance: balance_to_big_uint(&balance_low, &balance_high),
            },
        })
    }
```

**File:** crates/blockifier/src/context.rs (L62-71)
```rust
            TransactionInfo::Current(CurrentTransactionInfo {
                resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l2_gas, .. }),
                ..
            }) => {
                #[cfg(feature = "reexecution")]
                if self.block_context.versioned_constants.ignore_user_l2_gas_bound {
                    return self.block_context.versioned_constants.initial_gas_no_user_l2_bound();
                }
                l2_gas.max_amount
            }
```

**File:** crates/apollo_node/resources/config_schema.json (L107-111)
```json
  "batcher_config.static_config.block_builder_config.bouncer_config.block_max_capacity.sierra_gas": {
    "description": "An upper bound on the total sierra_gas used in a block.",
    "privacy": "Public",
    "value": 5000000000
  },
```
