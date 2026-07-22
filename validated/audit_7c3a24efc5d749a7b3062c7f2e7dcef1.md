### Title
Gateway Stateless Validator Skips `max_l2_gas_amount` Enforcement for Declare Transactions, Allowing Oversized Transactions into the Mempool - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

The `StatelessTransactionValidator::validate_resource_bounds` function explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. An unprivileged user can submit a `Declare` transaction with `l2_gas.max_amount = u64::MAX` and it will pass every gateway admission check, enter the mempool, and reach the batcher — violating the gateway's own configured admission policy that is correctly enforced for `Invoke` and `DeployAccount` transactions.

### Finding Description

In `crates/apollo_gateway/src/stateless_transaction_validator.rs` the `validate_resource_bounds` function contains an explicit branch that skips the `max_l2_gas_amount` check for `Declare` transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← no check at all
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The default configured limit is `max_l2_gas_amount = 1_210_000_000`. [2](#0-1) 

The stateful validator's `validate_resource_bounds` only checks the L2 gas *price* against the previous block's price threshold; it never checks the L2 gas *amount*: [3](#0-2) 

The blockifier's `check_fee_bounds` (called from `perform_pre_validation_stage`) checks whether `minimal_gas_amount > resource_bounds.max_amount` (i.e., the declared max is *too low*), but it does not enforce an upper bound on `max_amount`: [4](#0-3) 

The result is a three-layer gap: stateless validator skips the check, stateful validator never checks the amount, and the blockifier only rejects amounts that are *too small*. A `Declare` transaction with `l2_gas.max_amount = u64::MAX` passes all three layers and is admitted to the mempool.

The test suite confirms the gap is intentional and acknowledged: [5](#0-4) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's own policy (`max_l2_gas_amount`) is enforced for `Invoke` and `DeployAccount` but silently bypassed for `Declare`. Any user can submit a `Declare` transaction with `l2_gas.max_amount` far exceeding the configured limit. Such transactions are admitted to the mempool and forwarded to the batcher, consuming mempool slots and batcher resources. Because `verify_can_pay_committed_bounds` computes `committed_fee = max_l2_gas_amount × max_price_per_unit`, an extremely large `max_l2_gas_amount` combined with a non-zero price can cause arithmetic overflow in the fee computation, potentially producing a committed fee of zero or a small value, which would allow the transaction to pass the balance check even with a near-empty account. [6](#0-5) 

### Likelihood Explanation

**Likelihood: High.** No special permission or privileged role is required. Any user with a valid Starknet account can submit a `Declare` transaction via the public RPC endpoint. The bypass is unconditional — the branch is always taken for `Declare` regardless of the configured limit.

### Recommendation

Remove the `Declare` exemption in `validate_resource_bounds` and apply the same `max_l2_gas_amount` upper-bound check to all transaction types. The TODO comment at line 78 already acknowledges this gap; it should be resolved rather than deferred:

```rust
// Apply to all transaction types uniformly:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)` and `max_price_per_unit >= min_gas_price`.
2. Submit it to the gateway's `add_tx` endpoint.
3. Observe that `StatelessTransactionValidator::validate` returns `Ok(())` — the `MaxGasAmountTooHigh` error is never raised for `Declare`.
4. Observe that `StatefulTransactionValidator::validate_resource_bounds` also returns `Ok(())` — it only checks the price, not the amount.
5. The transaction is forwarded to the mempool and admitted, despite `l2_gas.max_amount` being `u64::MAX`, which is ~60× the configured `max_l2_gas_amount` of `1_210_000_000`.

The existing test `valid_l2_gas_amount_on_declare` in the test suite explicitly documents and asserts this behavior as passing: [5](#0-4)

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
