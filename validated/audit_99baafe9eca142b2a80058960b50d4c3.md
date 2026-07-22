### Title
`max_l2_gas_amount` Upper-Bound Not Enforced for Declare Transactions in Stateless Validator — (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` enforces the `max_l2_gas_amount` ceiling for Invoke and DeployAccount transactions but explicitly skips it for Declare transactions. An attacker can submit a `RpcDeclareTransactionV3` with `l2_gas.max_amount` far above the configured limit (1,210,000,000 in production) and, provided the sender account holds sufficient STRK balance to satisfy `verify_can_pay_committed_bounds`, the transaction passes every gateway check and is admitted to the mempool.

### Finding Description

In `validate_resource_bounds`, the upper-bound check reads:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

The empty `if let` arm is a deliberate no-op: Declare transactions are unconditionally exempted from the `max_l2_gas_amount` check. The production default is `max_l2_gas_amount = 1_210_000_000` (`config_schema.json`). A Declare transaction with `l2_gas.max_amount = u64::MAX` (or any value above the limit) passes this function without error.

The only downstream guard that could catch an oversized amount is `verify_can_pay_committed_bounds`, called inside `perform_pre_validation_stage` during stateful validation. It computes `max_possible_fee` using saturating arithmetic:

```rust
l2_gas.max_amount.saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into()))
```

Because the stateless validator still enforces `l2_gas.max_price_per_unit >= min_gas_price` (8,000,000,000 fri) for all transaction types, a Declare with `l2_gas.max_amount = u64::MAX` produces `max_possible_fee = u128::MAX`, which no account can pay, so that extreme case is rejected. However, for any value in the range `(max_l2_gas_amount, balance / min_gas_price]`, the transaction passes `verify_can_pay_committed_bounds` and is admitted. For example, with a balance of 10^22 fri (a realistic large account), the exploitable ceiling is approximately `10^22 / 8×10^9 ≈ 1.25×10^12`, roughly **1,000× the intended limit**.

Once admitted, `initial_sierra_gas()` returns `l2_gas.max_amount` directly as the Sierra gas budget for the transaction's execution:

```rust
TransactionInfo::Current(CurrentTransactionInfo {
    resource_bounds: ValidResourceBounds::AllResources(AllResourceBounds { l2_gas, .. }),
    ..
}) => { l2_gas.max_amount }
```

This gives the Declare transaction a gas budget orders of magnitude larger than any Invoke or DeployAccount transaction would be allowed.

The test `valid_l2_gas_amount_on_declare` in the test file explicitly confirms and documents this behavior as passing:

```rust
fn valid_l2_gas_amount_on_declare(…) {
    // l2_gas.max_amount = 200, max_l2_gas_amount = 100 → passes for Declare
    assert_matches!(tx_validator.validate(&tx), Ok(()));
}
```

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

A Declare transaction with `l2_gas.max_amount` above `max_l2_gas_amount` is an invalid transaction per the gateway's own admission rules. The stateless validator is the authoritative enforcement point for this limit; the stateful validator's balance check is not a substitute because it only rejects transactions whose `max_possible_fee` exceeds the sender's balance, not transactions that violate the protocol-level gas ceiling. Any sufficiently funded account can submit a Declare transaction that bypasses the ceiling, is admitted to the mempool, and executes with a Sierra gas budget far exceeding what the gateway intends to allow.

### Likelihood Explanation

Any user who can submit a Declare transaction (i.e., any account with sufficient STRK balance) can trigger this. No privileged access is required. The attacker-controlled field (`l2_gas.max_amount`) is a standard RPC field in `RpcDeclareTransactionV3`. The TODO comment in the source code confirms the developers are aware the check is absent.

### Recommendation

Apply the same `max_l2_gas_amount` upper-bound check to Declare transactions. Remove the empty `if let RpcTransaction::Declare(_) = tx { }` arm and let the existing `else if` branch cover all transaction types:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If a higher limit is intentionally desired for Declare transactions (e.g., because class compilation is more expensive), introduce a separate `max_l2_gas_amount_declare` config field with an explicit, documented value rather than leaving the check absent entirely.

### Proof of Concept

1. Build a `RpcDeclareTransactionV3` with:
   - A valid Sierra contract class (passes `validate_declare_tx`)
   - `l2_gas.max_amount = 10_000_000_000` (≈8× the production limit)
   - `l2_gas.max_price_per_unit = 8_000_000_000` (exactly `min_gas_price`)
   - Sender account balance ≥ `10_000_000_000 × 8_000_000_000 = 8×10^19` fri
2. Submit via `starknet_addDeclareTransaction`.
3. Observe: `StatelessTransactionValidator::validate` returns `Ok(())` — the `MaxGasAmountTooHigh` error is never raised.
4. The stateful validator's `verify_can_pay_committed_bounds` passes because the account balance covers `max_possible_fee = 8×10^19`.
5. The transaction is admitted to the mempool with `initial_sierra_gas = 10_000_000_000`, a gas budget 8× larger than any Invoke or DeployAccount transaction is permitted to claim.

The same Invoke transaction with identical `l2_gas.max_amount` would be rejected at step 3 with `MaxGasAmountTooHigh`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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
