### Title
Missing Upper Bound on `l2_gas.max_amount` for Declare Transactions Bypasses Gateway Admission Check - (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` enforces a `max_l2_gas_amount` ceiling on `l2_gas.max_amount` for Invoke and DeployAccount transactions, but explicitly skips that check for Declare transactions. Any user can submit a Declare transaction with `l2_gas.max_amount` set to an arbitrarily large value (up to `u64::MAX`) and the gateway's stateless validator will admit it, violating the invariant that all admitted transactions respect the configured gas-amount bound.

### Finding Description

In `validate_resource_bounds`, the upper-bound check is guarded by a type branch that silently no-ops for Declare:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← no check at all
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The production default for `max_l2_gas_amount` is 1,210,000,000: [2](#0-1) 

The test `valid_l2_gas_amount_on_declare` explicitly documents and asserts this bypass — a Declare transaction with `max_amount = GasAmount(200)` passes when the configured limit is 100: [3](#0-2) 

The same `l2_gas.max_amount` field is consumed by `TransactionContext::initial_sierra_gas()` as the execution gas budget: [4](#0-3) 

For Invoke/DeployAccount, exceeding `max_l2_gas_amount` is a hard rejection at the gateway. For Declare, the identical field is unchecked, so a Declare transaction with `l2_gas.max_amount = max_l2_gas_amount + 1` (or any larger value) passes stateless validation, enters the mempool, and — provided the sender holds sufficient balance to cover `max_amount × max_price_per_unit` — executes with a gas budget above the intended ceiling.

### Impact Explanation

A Declare transaction with `l2_gas.max_amount` set above `max_l2_gas_amount` (e.g., `1_210_000_001` when the limit is `1_210_000_000`) is admitted by the gateway's stateless validator when it should be rejected. If the sender's balance covers the committed fee (`max_amount × max_price_per_unit`), the blockifier's `verify_can_pay_committed_bounds` passes and the transaction executes with an above-limit Sierra gas budget. This breaks the admission invariant that the gateway enforces for all other transaction types. [5](#0-4) 

### Likelihood Explanation

The trigger is entirely unprivileged: any user who can submit an RPC Declare transaction can set `l2_gas.max_amount` to an arbitrary `u64` value. The bypass is unconditional — no special state, timing, or configuration is required. The TODO comment and the dedicated positive test case confirm the gap is present in the production code path.

### Recommendation

Remove the Declare-specific no-op branch and apply the same `max_l2_gas_amount` ceiling to Declare transactions:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher gas ceiling (e.g., for large Sierra programs), introduce a separate `max_l2_gas_amount_declare` configuration parameter rather than removing the check entirely.

### Proof of Concept

1. Construct a valid Declare V3 transaction with:
   - `l2_gas.max_amount = max_l2_gas_amount + 1` (e.g., `1_210_000_001`)
   - `l2_gas.max_price_per_unit >= min_gas_price` (passes the price floor check)
   - All other fields valid
2. Submit to the gateway's `add_transaction` endpoint.
3. Observe: `StatelessTransactionValidator::validate` returns `Ok(())` — the transaction is admitted.
4. For comparison, submit an identical Invoke transaction with the same `l2_gas.max_amount`; it is rejected with `MaxGasAmountTooHigh`.

The existing test already demonstrates step 3: [3](#0-2)

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

**File:** crates/blockifier/src/context.rs (L55-72)
```rust
    pub fn initial_sierra_gas(&self) -> GasAmount {
        match &self.tx_info {
            TransactionInfo::Deprecated(_)
            | TransactionInfo::Current(CurrentTransactionInfo {
                resource_bounds: ValidResourceBounds::L1Gas(_),
                ..
            }) => self.block_context.versioned_constants.initial_gas_no_user_l2_bound(),
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
