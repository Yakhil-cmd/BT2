### Title
Gateway Stateful Admission Checks Only L2 Gas Price, Ignoring L1 Gas and L1 Data Gas Price Thresholds — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds validation uses an **incomplete view** of a transaction's `AllResourceBounds`: it checks only the L2 gas price against the previous block's threshold, leaving `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` entirely unchecked. A transaction with zero (or arbitrarily low) L1 gas and L1 data gas prices passes gateway admission and enters the mempool, even though the blockifier will unconditionally reject it at pre-validation with `MaxGasPriceTooLow`. The gateway therefore accepts transactions it should reject, breaking the admission invariant.

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` reads only `strk_gas_prices.l2_gas_price` from the previous block and delegates to `validate_tx_l2_gas_price_within_threshold`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn validate_resource_bounds(&self, executable_tx: &ExecutableTransaction) -> ... {
    if self.config.validate_resource_bounds {
        // TODO(Arni): getnext_l2_gas_price from the block header.
        let previous_block_l2_gas_price = self
            .gateway_fixed_block_state_reader
            .get_block_info().await?
            .gas_prices
            .strk_gas_prices
            .l2_gas_price;                          // ← only L2 price fetched
        self.validate_tx_l2_gas_price_within_threshold(
            executable_tx.resource_bounds(),
            previous_block_l2_gas_price,            // ← only L2 price checked
        )?;
    }
    Ok(())
}
``` [1](#0-0) 

`validate_tx_l2_gas_price_within_threshold` explicitly acknowledges the gap with a TODO and only inspects `l2_gas.max_price_per_unit`:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(
    &self,
    tx_resource_bounds: ValidResourceBounds,
    previous_block_l2_gas_price: NonzeroGasPrice,
) -> ... {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit; // ← L2 only
            ...
            if tx_l2_gas_price.0 < threshold { return Err(...); }
        }
        ValidResourceBounds::L1Gas(_) => { /* No validation required */ }
    }
    Ok(())
}
``` [2](#0-1) 

`AllResourceBounds` carries three independent price fields:

```rust
pub struct AllResourceBounds {
    pub l1_gas: ResourceBounds,
    pub l2_gas: ResourceBounds,
    pub l1_data_gas: ResourceBounds,
}
``` [3](#0-2) 

The blockifier's `check_fee_bounds` (called from `perform_pre_validation_stage`) **does** check all three prices against the actual block prices:

```rust
ValidResourceBounds::AllResources(AllResourceBounds { l1_gas, l2_gas, l1_data_gas }) => {
    let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
        block_info.gas_prices.gas_price_vector(fee_type);
    vec![
        (L1Gas,     l1_gas,     minimal_gas_amount_vector.l1_gas,     *l1_gas_price),
        (L1DataGas, l1_data_gas, minimal_gas_amount_vector.l1_data_gas, *l1_data_gas_price),
        (L2Gas,     l2_gas,     minimal_gas_amount_vector.l2_gas,     *l2_gas_price),
    ]
}
// ...
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

The stateless validator also only checks `l2_gas.max_price_per_unit` against a static floor (`min_gas_price`), not against the dynamic previous-block L1 prices:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

### Impact Explanation

A transaction with `AllResourceBounds { l1_gas: { max_price: 0, max_amount: N }, l2_gas: { max_price: threshold+1, max_amount: M }, l1_data_gas: { max_price: 0, max_amount: K } }` passes every gateway check (stateless and stateful) and is admitted to the mempool. When the batcher later hands it to the blockifier, `check_fee_bounds` rejects it with `MaxGasPriceTooLow` for L1Gas before any execution occurs. The gateway has accepted a transaction that is definitively invalid under the current block's gas prices. This matches the allowed High impact: **"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."**

### Likelihood Explanation

Any unprivileged user can craft a V3 `AllResourceBounds` transaction with zero `l1_gas.max_price_per_unit` and a valid `l2_gas.max_price_per_unit`. No special knowledge or privilege is required. The gap is self-documented in production code with a TODO comment, confirming it is a known-incomplete check rather than an intentional design decision.

### Recommendation

Extend `validate_resource_bounds` to fetch `l1_gas_price` and `l1_data_gas_price` from the previous block's `strk_gas_prices` and apply the same `min_gas_price_percentage` threshold check to `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` inside `validate_tx_l2_gas_price_within_threshold` (or a renamed successor). This mirrors the complete three-price check already performed by `check_fee_bounds` in the blockifier, closing the gap between gateway admission and blockifier pre-validation.

### Proof of Concept

1. Construct a V3 invoke transaction with:
   ```
   AllResourceBounds {
       l1_gas:      { max_amount: 1, max_price_per_unit: 0 },
       l2_gas:      { max_amount: 1, max_price_per_unit: <previous_block_l2_gas_price> },
       l1_data_gas: { max_amount: 1, max_price_per_unit: 0 },
   }
   ```
2. Submit to the gateway. `StatelessTransactionValidator::validate_resource_bounds` passes because `max_possible_fee(Tip::ZERO) > 0` (L2 contribution is non-zero) and `l2_gas.max_price_per_unit >= min_gas_price`.
3. `StatefulTransactionValidator::validate_resource_bounds` passes because only `l2_gas_price` is compared against the threshold — `l1_gas.max_price_per_unit = 0` is never examined.
4. The transaction is admitted to the mempool.
5. When the batcher executes it, `AccountTransaction::check_fee_bounds` compares `l1_gas.max_price_per_unit (0) < actual_l1_gas_price (> 0)` and returns `TransactionFeeError::InsufficientResourceBounds { MaxGasPriceTooLow { resource: L1Gas, ... } }`, rejecting the transaction that the gateway already accepted. [2](#0-1) [1](#0-0) [6](#0-5)

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

**File:** crates/starknet_api/src/transaction/fields.rs (L479-483)
```rust
pub struct AllResourceBounds {
    pub l1_gas: ResourceBounds,
    pub l2_gas: ResourceBounds,
    pub l1_data_gas: ResourceBounds,
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-458)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L71-76)
```rust
        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }
```
