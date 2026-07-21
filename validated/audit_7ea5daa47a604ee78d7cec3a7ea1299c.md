### Title
Gateway Stateful Validator Omits L1 Gas and L1 Data Gas Price Threshold Checks, Admitting Transactions That Will Fail Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The gateway's stateful validator enforces a minimum price threshold only for the L2 gas dimension. L1 gas and L1 data gas `max_price_per_unit` fields are never compared against the previous block's prices. A transaction with `l1_gas.max_price_per_unit = 0` (or any value below the live L1 gas price) passes both the stateless and stateful gateway checks and is admitted to the mempool, but is then unconditionally rejected by the blockifier's `check_fee_bounds` at execution time. The gateway therefore admits transactions it knows will never execute.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads the previous block's L2 gas price and delegates to `validate_tx_l2_gas_price_within_threshold`:

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
            // threshold = min_gas_price_percentage% * previous_block_l2_gas_price
            if tx_l2_gas_price.0 < threshold { return Err(...) }
        }
        ValidResourceBounds::L1Gas(_) => { /* No validation required for legacy transactions. */ }
    }
    Ok(())
}
``` [1](#0-0) 

The function name and the TODO comment both acknowledge that only L2 gas price is validated. `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never compared against any threshold.

The stateless validator has the same gap: it enforces `l2_gas.max_price_per_unit >= min_gas_price` (default 8 Gwei) but has no floor for L1 or L1 data gas prices: [2](#0-1) 

The zero-bounds guard only checks that the *total* fee is non-zero, so a transaction with `l2_gas.max_amount > 0` and `l2_gas.max_price_per_unit >= min_gas_price` passes even when both `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0`. [3](#0-2) 

At execution time the blockifier's `check_fee_bounds` inside `perform_pre_validation_stage` checks **all three** gas prices against the live block prices:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

Because the production configuration sets `min_l1_gas_price_wei = 1_000_000_000` (1 Gwei), the L1 gas price is always non-zero in production: [5](#0-4) 

Any `AllResources` transaction with `l1_gas.max_price_per_unit = 0` will therefore be admitted by the gateway and unconditionally rejected by the blockifier.

### Impact Explanation

Matches **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

The gateway's admission invariant is broken: it accepts transactions that are structurally invalid with respect to the current gas-price regime. Every such transaction occupies a mempool slot, consumes gateway validation resources (including the blockifier `__validate__` call for invoke transactions), and is silently dropped at batcher execution time without ever being included in a block. An unprivileged attacker can continuously submit such transactions to degrade mempool quality and waste sequencer resources.

### Likelihood Explanation

Medium. The attack requires only a well-formed `AllResources` invoke transaction with `l1_gas.max_price_per_unit = 0` and a valid L2 gas price. No special privileges, keys, or deployed contracts are needed. The condition is stable across all blocks as long as the L1 gas price remains non-zero (which is always true in production).

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or replace it with a general `validate_all_gas_prices_within_threshold`) to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the corresponding previous-block prices scaled by `min_gas_price_percentage`. The stateless validator's `min_gas_price` check should similarly be applied to all three gas dimensions, not only L2 gas. The existing TODO comment at line 358 already identifies this gap. [6](#0-5) 

### Proof of Concept

1. Construct a V3 invoke transaction with `AllResources` bounds:
   - `l2_gas.max_price_per_unit = 8_000_000_001` (above the 8 Gwei stateless floor)
   - `l2_gas.max_amount = 1`
   - `l1_gas.max_price_per_unit = 0`
   - `l1_data_gas.max_price_per_unit = 0`
2. Submit to the gateway. **Stateless check passes**: total fee = `1 * 8_000_000_001 > 0`; L2 gas price ≥ `min_gas_price`.
3. **Stateful check passes**: `validate_tx_l2_gas_price_within_threshold` only inspects `l2_gas.max_price_per_unit`; L1 fields are ignored.
4. Transaction is inserted into the mempool.
5. When the batcher calls `perform_pre_validation_stage`, `check_fee_bounds` compares `l1_gas.max_price_per_unit (0)` against the live L1 gas price (≥ 1 Gwei). The check fails with `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas, ... }`.
6. The transaction is never included in any block; the mempool slot is wasted. [7](#0-6) [8](#0-7)

### Citations

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L64-88)
```rust
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

**File:** crates/apollo_node/resources/config_schema.json (L2727-2731)
```json
  "consensus_manager_config.context_config.dynamic_config.min_l1_gas_price_wei": {
    "description": "The minimum L1 gas price in wei.",
    "privacy": "Public",
    "value": 1000000000
  },
```
