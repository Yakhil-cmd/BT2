### Title
Gateway Stateful Validator Uses Previous Block L2 Gas Price Instead of Next Block Price, Admitting Transactions That Will Fail Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` gates mempool admission using the **previous** block's L2 gas price, but every admitted transaction executes in the **next** block whose EIP-1559 price may be strictly higher. Transactions whose `max_price_per_unit` sits between the two prices pass the gateway check yet are rejected by the blockifier's `check_fee_bounds` at execution time, meaning the gateway admits transactions that are invalid for the block they will actually run in.

### Finding Description

In `validate_resource_bounds` the validator reads the previous block's STRK L2 gas price and forwards it to `validate_tx_l2_gas_price_within_threshold`:

```rust
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
``` [1](#0-0) 

The threshold comparison is:

```rust
if tx_l2_gas_price.0 < threshold {   // threshold = min_gas_price_percentage% of PREVIOUS block price
    return Err(...)
}
``` [2](#0-1) 

The production default is `min_gas_price_percentage = 100`, so the gate is effectively `tx_price >= previous_block_price`. [3](#0-2) 

Meanwhile, the blockifier's `check_fee_bounds` — called inside `perform_pre_validation_stage` for every transaction that reaches execution — compares the transaction's price against the **current block context** price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

The block context price is the **next** block's price, computed by `calculate_next_base_gas_price` using EIP-1559 logic:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [5](#0-4) 

When the previous block is above the gas target, `next_price > previous_price`. Any transaction with `previous_price <= tx_price < next_price` clears the gateway but fails `check_fee_bounds` with `TransactionPreValidationError`, so it is never included in a block. The TODO comment in the gateway code explicitly acknowledges the wrong price is being used.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An unprivileged user can craft a V3 `AllResources` transaction whose `l2_gas.max_price_per_unit` equals exactly the previous block's L2 gas price. During any period of above-target block utilization (the common case on a busy network), the EIP-1559 formula raises the next block's price above the previous block's price. The gateway admits the transaction; the blockifier rejects it at pre-validation. The transaction occupies a mempool slot, consumes gateway validation resources (including a full blockifier `__validate__` run), and is never sequenced. Because pre-validation failure charges no fee, the attacker bears no cost beyond the submission itself.

### Likelihood Explanation

The condition `next_block_price > previous_block_price` holds whenever the previous block's gas usage exceeds the gas target — a routine occurrence on a loaded network. The price gap per block is bounded by `price / gas_price_max_change_denominator`, so the exploitable window is narrow per block but persistent across sustained load. The TODO comment confirms the developers already identified this as a defect.

### Recommendation

Replace the previous-block price lookup with a forward-looking estimate of the next block's L2 gas price. The `calculate_next_base_gas_price` function already implements the EIP-1559 formula; the gateway should call it with the previous block's price, gas used, and gas target to derive the threshold before comparing against the transaction's `max_price_per_unit`. This is exactly what the TODO comment requests.

### Proof of Concept

1. Observe that the previous block's STRK L2 gas price is `P` and its gas usage exceeded the target (e.g., block is 80 % full).
2. `calculate_next_base_gas_price` yields `P' = P + P * gas_delta / (gas_target * denominator)` where `P' > P`.
3. Submit an `AllResources` invoke transaction with `l2_gas.max_price_per_unit = P` (satisfies `P >= 100% * P`).
4. `validate_tx_l2_gas_price_within_threshold` passes: `P >= threshold`.
5. `extract_state_nonce_and_run_validations` succeeds; the transaction enters the mempool.
6. When the batcher pulls the transaction and the blockifier runs `check_fee_bounds` against the next block context (price `P'`), it finds `P < P'` and raises `MaxGasPriceTooLow`.
7. The transaction is rejected at pre-validation, no fee is charged, and the mempool slot is wasted. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-241)
```rust
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
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

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L128-139)
```rust
    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

    // Sanity check: ensure direction of change is correct
    assert!(
        gas_used > gas_target && adjusted_price_u256 >= price_u256
            || gas_used <= gas_target && adjusted_price_u256 <= price_u256
    );

    // Price should not realistically exceed u128::MAX, bound to avoid theoretical overflow.
    let adjusted_price = u128::try_from(adjusted_price_u256).unwrap_or(u128::MAX);
    GasPrice(max(adjusted_price, min_gas_price.0))
```
