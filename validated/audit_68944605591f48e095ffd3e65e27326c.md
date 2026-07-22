### Title
Gateway `validate_resource_bounds` admits transactions priced at the previous-block L2 gas price that `check_fee_bounds` will reject at batcher execution time when EIP-1559 raises the price — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful validator checks a transaction's `max_l2_gas_price` against the **previous block's** L2 gas price. The batcher executes those same transactions using the **next block's** L2 gas price, computed via EIP-1559 (`calculate_next_base_gas_price`). When blocks are above the gas target, the next block's price is strictly higher than the previous block's price. A transaction whose `max_l2_gas_price` is calibrated to the previous block's price passes gateway admission but fails `check_fee_bounds` at batcher pre-validation, causing it to be silently dropped from sequencing.

---

### Finding Description

**Step 1 — Gateway threshold uses previous-block price**

`StatefulTransactionValidator::validate_resource_bounds` fetches the previous block's L2 gas price and enforces a percentage threshold:

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

With the default `min_gas_price_percentage = 100`, the admission condition is exactly `tx_l2_gas_price >= previous_block_l2_gas_price`. [2](#0-1) 

The TODO comment in the source code explicitly acknowledges the bug: the gateway should be using the **next** block's L2 gas price, not the previous block's.

**Step 2 — Gateway blockifier validation also uses previous-block gas prices**

`run_validate_entry_point` increments the block number but carries over the previous block's gas prices unchanged:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

So `check_fee_bounds` inside `perform_pre_validation_stage` during gateway validation also sees the previous block's gas prices — the same price the threshold check used.

**Step 3 — Batcher executes with EIP-1559-adjusted next-block price**

The consensus orchestrator computes the next block's L2 gas price via `calculate_next_base_gas_price`:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [4](#0-3) 

When `gas_used > gas_target` (any block above 60% full), the next block's price is strictly higher. The batcher then pushes this new price to the mempool: [5](#0-4) 

**Step 4 — `check_fee_bounds` rejects the transaction at batcher execution**

`AccountTransaction::check_fee_bounds` compares the transaction's `max_price_per_unit` against the block context's actual gas price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(
        ResourceBoundsError::MaxGasPriceTooLow { ... }
    );
}
``` [6](#0-5) 

This is called from `perform_pre_validation_stage`, which is a non-revertible pre-execution check: [7](#0-6) 

A `TransactionPreValidationError` here means the transaction is rejected entirely — no fee charged, nonce not consumed, transaction not included in the block.

---

### Impact Explanation

The gateway admits a transaction with `max_l2_gas_price = P_prev` (previous block price). The batcher's block context carries `P_next > P_prev` (EIP-1559 adjusted). `check_fee_bounds` fires `MaxGasPriceTooLow` and the transaction is dropped from sequencing. The user's transaction was accepted by the gateway/mempool but can never be sequenced as long as gas prices remain elevated. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

This occurs naturally whenever any block exceeds the gas target (60% of `max_block_size`). From the snapshot tests, a block at 75% capacity raises the next block's price by ~1.04% (30 B → 30.3 B fri). A user who sets `max_l2_gas_price` exactly at the gateway's admission floor — the previous block's price — will have their transaction rejected by the batcher on every congested block. No adversarial action is required; normal network load triggers the condition. [8](#0-7) 

---

### Recommendation

Replace the previous-block price lookup in `validate_resource_bounds` with the EIP-1559-computed next-block price, as the existing TODO comment already prescribes:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The gateway should call `calculate_next_l2_gas_price_for_fin` (or an equivalent) using the previous block's gas usage and price to derive `P_next`, then use `P_next` as the threshold. This ensures that any transaction admitted by the gateway will also satisfy `check_fee_bounds` in the batcher's block context. [9](#0-8) 

---

### Proof of Concept

1. Previous block: L2 gas price `P = 30_000_000_000` fri, gas used = 75% of max block size (above 60% target).
2. EIP-1559 computes next block price: `P' = 30_312_500_000` fri (+1.04%).
3. User submits an `AllResources` V3 invoke with `l2_gas.max_price_per_unit = 30_000_000_000`.
4. **Gateway `validate_resource_bounds`**: `30_000_000_000 >= 100% × 30_000_000_000` → **admitted**.
5. **Gateway blockifier validation** (`run_validate_entry_point`): block context carries `P` (previous block prices) → `check_fee_bounds` passes.
6. Transaction enters mempool.
7. **Batcher execution**: block context carries `P' = 30_312_500_000` → `check_fee_bounds` fires `MaxGasPriceTooLow { max_gas_price: 30_000_000_000, actual_gas_price: 30_312_500_000 }` → transaction rejected, never sequenced. [10](#0-9) [11](#0-10)

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L55-77)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L128-130)
```rust
    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

```

**File:** crates/apollo_batcher/src/batcher.rs (L375-383)
```rust
        mempool_client
            .update_gas_price(
                propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
            )
            .await
            .map_err(|err| {
                error!("Failed to update gas price in mempool: {}", err);
                BatcherError::InternalError
            })?;
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/test.rs (L22-61)
```rust
#[rstest]
#[case::high_congestion(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 3 / 4),
    VERSIONED_CONSTANTS.max_block_size / 2,
    GasPrice(30312500000),
)]
#[case::low_congestion(
    VERSIONED_CONSTANTS.max_block_size / 4,
    VERSIONED_CONSTANTS.max_block_size / 2,
    GasPrice(29687500000),
)]
#[case::stable(
    VERSIONED_CONSTANTS.max_block_size / 2,
    VERSIONED_CONSTANTS.max_block_size / 2,
    INIT_PRICE
)]
#[case::high_congestion_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 9 / 10),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4 / 5), // Gas target 80%
    GasPrice(30078125000)
)]
#[case::low_congestion_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 / 4),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4 / 5), // Gas target 80%
    GasPrice(29570312500)
)]
#[case::stable_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4/5),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4/5), // Gas target 80%
    INIT_PRICE
)]
fn price_calculation_snapshot(
    #[case] gas_used: GasAmount,
    #[case] gas_target: GasAmount,
    #[case] expected: GasPrice,
) {
    let min_gas_price = VERSIONED_CONSTANTS.min_gas_price;
    let actual = calculate_next_base_gas_price(INIT_PRICE, gas_used, gas_target, min_gas_price);
    assert_eq!(actual, expected);
}
```
