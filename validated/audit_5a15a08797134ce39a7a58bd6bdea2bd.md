### Title
Gateway Stateful Validator Checks L2 Gas Price Against Previous Block Instead of Execution Block, Causing Systematic Wrong Admission and Rejection Decisions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `validate_resource_bounds` function in `StatefulTransactionValidator` checks a transaction's `max_price_per_unit` against the **previous block's** L2 gas price. The actual blockifier execution, however, enforces the **current (next) block's** L2 gas price. With `gas_price_max_change_denominator = 48` and the current block-size parameters, the L2 gas price can shift by up to ~9.5% per block. This creates a systematic mismatch: the gateway admits transactions that will fail at execution (when price rises) and rejects transactions that would succeed at execution (when price falls). The developers acknowledge the root cause with an inline TODO.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the **previous** block's L2 gas price and compares it against the transaction's `max_price_per_unit`:

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

The threshold is computed as `min_gas_price_percentage% × previous_block_l2_gas_price` (default `min_gas_price_percentage = 100`):

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...GAS_PRICE_TOO_LOW...);
}
``` [2](#0-1) 

When the blockifier later executes the transaction, `check_fee_bounds` enforces the **current block's** L2 gas price — the price that was computed from the previous block via EIP-1559:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(
        ResourceBoundsError::MaxGasPriceTooLow { ... }
    );
}
``` [3](#0-2) 

The EIP-1559 formula is:

```
price_change = price × gas_delta / (gas_target × gas_price_max_change_denominator)
``` [4](#0-3) 

With `gas_price_max_change_denominator = 48`, `max_block_size = 5,800,000,000`, and `gas_target = 1,040,000,000` (latest versioned constants):

```
max_price_change = price × (5,800,000,000 − 1,040,000,000) / (1,040,000,000 × 48)
                 = price × 4,760,000,000 / 49,920,000,000
                 ≈ price × 9.5%
``` [5](#0-4) 

The gateway's `run_validate_entry_point` increments the block number by 1 but **does not update the gas prices** to reflect the next block's EIP-1559 price:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
// gas_prices are NOT updated — still previous block's prices
let block_context = BlockContext::new(block_info, ...);
``` [6](#0-5) 

This means both the stateful pre-check and the gateway's blockifier validation use the previous block's gas prices, while the batcher's actual execution uses the current block's prices.

---

### Impact Explanation

**Wrong admission (invalid transaction accepted):** A user submits a transaction with `max_price_per_unit = P` (exactly the previous block's price, satisfying the 100% threshold). The gateway admits it. The next block's price is `P' ≈ P × 1.095` (full block). At execution, `check_fee_bounds` finds `P < P'` and returns `MaxGasPriceTooLow`. The transaction fails at execution despite being admitted — the gateway accepted an invalid transaction.

**Wrong rejection (valid transaction rejected):** After a congested block with price `P`, the next block is lightly used, so the execution price drops to `P' < P`. A user submits with `max_price_per_unit = P'` (sufficient for execution). The gateway rejects it because `P' < 100% × P`. A valid transaction is denied admission.

Both outcomes match: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The L2 gas price changes every block. With `gas_price_max_change_denominator = 48` and the current block-size ratio (gas_target ≈ 18–27% of max_block_size in recent versions), a moderately congested block produces a multi-percent price increase. Any user whose `max_price_per_unit` falls in the gap between `previous_block_price` and `next_block_price` is affected. This is a systematic, per-block occurrence — not a rare edge case.

---

### Recommendation

Replace the `previous_block_l2_gas_price` read with the **computed next block L2 gas price** (applying the EIP-1559 formula to the previous block's price and gas usage). The TODO comment in the code already identifies this exact fix:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The `calculate_next_l2_gas_price_for_fin` function in `crates/apollo_consensus_orchestrator/src/fee_market/mod.rs` already implements this computation and should be reused here. [7](#0-6) 

---

### Proof of Concept

**Setup (latest versioned constants v0_14_4):**
- `gas_price_max_change_denominator = 48`
- `gas_target = 1,040,000,000`
- `max_block_size = 5,800,000,000`
- `min_gas_price_percentage = 100` (default)

**Steps:**

1. Block N is completely full (`gas_used = 5,800,000,000`).
2. Previous block L2 gas price: `P = 8,000,000,000 fri` (min_gas_price).
3. Next block L2 gas price (computed by EIP-1559):
   - `gas_delta = 5,800,000,000 − 1,040,000,000 = 4,760,000,000`
   - `price_change = 8,000,000,000 × 4,760,000,000 / (1,040,000,000 × 48) = 762,820,512`
   - `P' = 8,000,000,000 + 762,820,512 = 8,762,820,512 fri`
4. User submits an `AllResources` invoke transaction with `l2_gas.max_price_per_unit = 8,000,000,000`.
5. **Gateway admission check:** `8,000,000,000 >= 100% × 8,000,000,000` → **PASS** → transaction admitted to mempool.
6. **Batcher execution:** `check_fee_bounds` uses block N+1's price `P' = 8,762,820,512`. Checks `8,000,000,000 >= 8,762,820,512` → **FAIL** → `ResourceBoundsError::MaxGasPriceTooLow`.
7. Transaction fails at execution despite being admitted by the gateway. [8](#0-7) [9](#0-8) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-240)
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-330)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-458)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L54-77)
```rust
/// Compute the next L2 gas price (for the fin or for updating state). Respects override when set.
pub fn calculate_next_l2_gas_price_for_fin(
    current_l2_gas_price: GasPrice,
    height: BlockNumber,
    l2_gas_used: GasAmount,
    override_l2_gas_price_fri: Option<u128>,
    min_l2_gas_price_per_height: &[PricePerHeight],
    fee_actual: Option<GasPrice>,
) -> GasPrice {
    if let Some(override_value) = override_l2_gas_price_fri {
        info!(
            "L2 gas price ({}) is not updated, remains on override value of {override_value} fri",
            current_l2_gas_price.0
        );
        return GasPrice(override_value);
    }
    let gas_target = VersionedConstants::latest_constants().gas_target;
    let config_min = get_min_gas_price_for_height(height, min_l2_gas_price_per_height);
    let effective_min = match fee_actual {
        Some(fa) => GasPrice(max(config_min.0, fa.0)),
        None => config_min,
    };
    calculate_next_base_gas_price(current_l2_gas_price, l2_gas_used, gas_target, effective_min)
}
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L124-129)
```rust
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_4.json (L1-9)
```json
{
    "fee_proposal_margin_ppt": 2,
    "fee_proposal_window_size": 10,
    "gas_price_max_change_denominator": 48,
    "gas_target": 1040000000,
    "max_block_size": 5800000000,
    "min_gas_price": "0x1dcd65000",
    "l1_gas_price_margin_percent": 10
}
```
