### Title
Gateway Stateless Validator Skips `max_l2_gas_amount` Check for Declare Transactions, Admitting Invalid Transactions to Mempool - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The `StatelessTransactionValidator::validate_resource_bounds` function explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. Any Declare transaction with `l2_gas.max_amount` exceeding the configured limit (1,210,000,000 in production) passes gateway admission and enters the mempool. During blockifier pre-validation, `verify_can_pay_committed_bounds` computes `max_possible_fee` using saturating arithmetic, which saturates to `u128::MAX` for extreme values, causing the transaction to always fail the balance check. The nonce is not consumed, but the transaction was admitted to the mempool in violation of the gateway's own admission rule.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` check is gated behind a type check that explicitly skips Declare transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The production default for `max_l2_gas_amount` is `1_210_000_000`: [2](#0-1) 

The test `valid_l2_gas_amount_on_declare` explicitly confirms this bypass is intentional: a Declare transaction with `max_amount = 200` passes when `max_l2_gas_amount = 100`: [3](#0-2) 

The asymmetry is:
- **Gateway admission (stateless)**: `max_l2_gas_amount` check is **skipped** for Declare transactions.
- **Blockifier pre-validation**: `verify_can_pay_committed_bounds` computes `max_possible_fee` which **includes** `l2_gas.max_amount * l2_gas.max_price_per_unit` using saturating arithmetic.

`max_possible_fee` uses `saturating_mul` and `saturating_add`: [4](#0-3) 

With `max_l2_gas_amount = u64::MAX` and `max_l2_gas_price = 8_000_000_000` (the minimum allowed), the product saturates to `u128::MAX`. `verify_can_pay_committed_bounds` then checks whether the account balance covers `u128::MAX`: [5](#0-4) 

No account can hold `u128::MAX` fee tokens, so the transaction always fails at blockifier pre-validation with `ResourcesBoundsExceedBalance`. The nonce is not incremented (pre-validation failure), but the transaction was admitted to the mempool in violation of the gateway's own `max_l2_gas_amount` rule.

The `perform_pre_validation_stage` call sequence confirms the order: nonce handling, then `check_fee_bounds`, then `verify_can_pay_committed_bounds`: [6](#0-5) 

### Impact Explanation

**High** — Mempool/gateway admission accepts invalid Declare transactions that violate the `max_l2_gas_amount` admission rule. An attacker can submit Declare transactions with arbitrarily large `l2_gas.max_amount` values (up to `u64::MAX`), bypassing the gateway's DoS protection for this resource dimension. These transactions enter the mempool, consume sequencer resources during compilation (class manager) and blockifier pre-validation, and are then silently dropped. The `declare_compilation_semaphore` (40 slots) provides partial mitigation but does not prevent the admission bypass itself.

### Likelihood Explanation

Any unprivileged user can submit a Declare transaction with `l2_gas.max_amount > 1_210_000_000`. The bypass requires no special knowledge beyond reading the open-source gateway code and the TODO comment that explicitly acknowledges the missing check. The `min_gas_price` check (line 71–76) still applies, so the attacker must set a non-zero L2 gas price, but this is trivially satisfied.

### Recommendation

Apply the `max_l2_gas_amount` check uniformly to all transaction types, including Declare. Remove the `if let RpcTransaction::Declare(_) = tx { }` branch and let the existing `else if` apply unconditionally:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If Declare transactions legitimately require a higher L2 gas ceiling (e.g., for compilation), introduce a separate `max_l2_gas_amount_declare` config field rather than removing the check entirely.

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and `resource_bounds.l2_gas.max_price_per_unit = GasPrice(8_000_000_000)` (the minimum allowed by `min_gas_price`).
2. Submit to the gateway via `POST /gateway/add_transaction`.
3. `StatelessTransactionValidator::validate_resource_bounds` reaches line 79, matches `RpcTransaction::Declare(_)`, and returns `Ok(())` without checking the amount.
4. `StatefulTransactionValidator::validate_resource_bounds` checks only the L2 gas price threshold — passes.
5. The transaction is admitted to the mempool via `mempool_client.add_tx(...)`.
6. When the batcher pulls the transaction and the blockifier calls `perform_pre_validation_stage`, `verify_can_pay_committed_bounds` computes `max_possible_fee = u128::MAX` (saturated) and returns `ResourcesBoundsExceedBalance`.
7. The transaction is dropped from the block; the nonce is not consumed. The attacker can repeat indefinitely, each time consuming compilation semaphore slots and blockifier pre-validation CPU.

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
