### Title
`max_l2_gas_amount` Upper-Bound Not Enforced for Declare Transactions in Stateless Validator — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` enforces a configurable `max_l2_gas_amount` ceiling for `Invoke` and `DeployAccount` transactions but explicitly skips that check for `Declare` transactions via an empty branch. No downstream guard in the stateful validator or blockifier re-applies the same ceiling on the *amount* field, so a `Declare` transaction carrying `l2_gas.max_amount = u64::MAX` clears every admission gate and reaches the mempool.

---

### Finding Description

In `crates/apollo_gateway/src/stateless_transaction_validator.rs` the relevant block is:

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

The empty `if let RpcTransaction::Declare(_) = tx {}` arm is a deliberate no-op that causes the `else if` to be unreachable for `Declare`. The companion test `valid_l2_gas_amount_on_declare` (lines 191–201 of the test file) explicitly asserts that a `Declare` with `max_amount = 200` passes when `max_l2_gas_amount = 100`, confirming the bypass is intentional but unguarded.

**Downstream guard analysis — none close the gap on the *amount*:**

| Stage | What is checked | Covers amount ceiling? |
|---|---|---|
| Stateless `validate_resource_bounds` | price ≥ `min_gas_price`; amount ≤ `max_l2_gas_amount` | **No for Declare** |
| Stateful `validate_resource_bounds` | price ≥ threshold fraction of previous block price | No |
| Blockifier `check_fee_bounds` | `minimal_gas_amount ≤ resource_bounds.max_amount` | No (lower-bound only) |
| `verify_can_pay_committed_bounds` | balance ≥ `max_l2_gas_amount × max_price_per_unit + …` | Partial — bypassed when `max_price_per_unit = 0` |

When `min_gas_price = 0` (a valid configuration, as the stateless check is `< self.config.min_gas_price`), an attacker may set `l2_gas.max_price_per_unit = 0` alongside `l2_gas.max_amount = u64::MAX`. The zero-fee guard (`max_possible_fee == Fee(0)`) is satisfied by keeping any other resource bound non-zero (e.g. `l1_gas.max_amount > 0`). `verify_can_pay_committed_bounds` then computes `committed_fee = 0 × u64::MAX + l1_contribution`, which the account can cover, and the transaction is admitted to the mempool.

Even when `min_gas_price > 0`, the stateless validator still admits the transaction (the check is simply skipped), and the only backstop is the balance check — which is a stateful, per-account guard, not the intended stateless admission filter.

---

### Impact Explanation

The gateway's stateless validator is the first line of defence against malformed resource-bound fields. Bypassing the `max_l2_gas_amount` ceiling for `Declare` transactions means:

1. **Invalid transactions admitted** — a `Declare` with `l2_gas.max_amount = u64::MAX` passes the stateless gate that is supposed to reject it, satisfying the "High — Mempool/gateway/RPC admission accepts invalid transactions" criterion.
2. **Fee-computation integrity** — `max_possible_fee` is computed as `max_l2_gas_amount × max_price_per_unit`. With a `u64::MAX` amount and any non-zero price, the product overflows `u128` arithmetic in `verify_can_pay_committed_bounds`, potentially producing an incorrect (wrapped) fee value that could allow an under-funded account to pass the balance check.
3. **Inconsistent admission policy** — the invariant "no transaction with `l2_gas.max_amount > max_l2_gas_amount` enters the mempool" is broken for one of the three transaction types, creating an asymmetric attack surface.

---

### Likelihood Explanation

Any unprivileged user can submit a well-formed `Declare` transaction (valid Sierra class, valid compiled-class hash, valid signature) with `l2_gas.max_amount` set to an arbitrary value exceeding `config.max_l2_gas_amount`. The bypass requires no special account state when `min_gas_price = 0`. When `min_gas_price > 0`, the attacker still bypasses the stateless check; the only remaining barrier is the balance check, which is a weaker, per-account guard.

---

### Recommendation

Remove the empty `if let RpcTransaction::Declare(_) = tx {}` branch and apply the same `max_l2_gas_amount` ceiling unconditionally:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Update the test `valid_l2_gas_amount_on_declare` to expect a `MaxGasAmountTooHigh` error when the amount exceeds the configured ceiling, and add a separate positive-flow test for `Declare` transactions whose `max_l2_gas_amount` is within bounds.

---

### Proof of Concept

```rust
// Craft a Declare RPC transaction with max_l2_gas_amount = u64::MAX
let rpc_tx = rpc_declare_tx(
    declare_tx_args!(
        resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(u64::MAX),          // exceeds max_l2_gas_amount
                max_price_per_unit: GasPrice(0),          // zero price → zero L2 fee
            },
            l1_gas: ResourceBounds {
                max_amount: GasAmount(1),
                max_price_per_unit: GasPrice(1),          // non-zero to pass zero-fee guard
            },
            ..Default::default()
        }),
    ),
    valid_sierra_contract_class(),
);

let validator = StatelessTransactionValidator {
    config: StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 1_000_000,   // ceiling set to 1 M
        min_gas_price: 0,
        ..Default::default()
    },
};

// Passes — should have returned MaxGasAmountTooHigh
assert_matches!(validator.validate(&rpc_tx), Ok(()));
```

The transaction then proceeds through `convert_rpc_tx_to_internal`, stateful validation (price check only), `verify_can_pay_committed_bounds` (L2 fee = 0, L1 fee covered by balance), and is inserted into the mempool — despite carrying a `max_l2_gas_amount` two orders of magnitude above the configured ceiling. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L243-271)
```rust
#[rstest]
#[case::max_l2_gas_amount_too_high(
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount + 1),
                max_price_per_unit: GasPrice(DEFAULT_VALIDATOR_CONFIG.min_gas_price),
            },
            ..Default::default()
        },
        ..Default::default()
    },
    StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: GasAmount(DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount + 1),
        max_gas_amount: DEFAULT_VALIDATOR_CONFIG.max_l2_gas_amount
    },
)]
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
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
