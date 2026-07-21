### Title
Gateway `run_validate_entry_point` Uses Previous-Block Gas Prices for `check_fee_bounds` While Batcher Executes at EIP-1559-Adjusted Next-Block Prices — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `run_validate_entry_point` builds a `BlockContext` from the **previous block's gas prices** (only incrementing the block number), then runs `check_fee_bounds` inside `StatefulValidator::perform_validations`. The batcher, however, receives the **next block's gas prices** computed by the EIP-1559-style fee market algorithm (`calculate_next_l2_gas_price_for_fin`) from the consensus orchestrator. Because the two `check_fee_bounds` calls use different gas prices, the gateway makes wrong admission decisions: it admits transactions that will fail at batcher execution when the price rises, and rejects valid transactions when the price falls.

### Finding Description

**Gateway side — stale gas prices in `run_validate_entry_point`:**

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:323-330
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
// ↑ Only the block number is bumped; all gas prices remain from the previous block.
let block_context = BlockContext::new(block_info, ...);
...
blockifier_validator.validate(account_tx)  // runs check_fee_bounds with P_prev
```

`StatefulValidator::perform_validations` calls `tx.perform_pre_validation_stage(self.state(), &tx_context)`, which calls `self.check_fee_bounds(tx_context)`. That function compares `tx.resource_bounds.max_price_per_unit` against `block_context.block_info.gas_prices.l2_gas_price` — which is `P_prev`, the **previous** block's price.

The same stale-price problem is acknowledged in `validate_resource_bounds`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:229
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
```

**Batcher side — correct next-block gas prices:**

The consensus orchestrator computes the next block's L2 gas price via `calculate_next_l2_gas_price_for_fin` (an EIP-1559 algorithm) and passes it to the batcher in `ProposeBlockInput.block_info`. The batcher immediately propagates it to the mempool:

```rust
// crates/apollo_batcher/src/batcher.rs:375-383
mempool_client
    .update_gas_price(
        propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
    )
    .await
```

The same `block_info` is forwarded to the blockifier via `create_block_builder`, so `check_fee_bounds` during actual execution uses `P_next`.

**The EIP-1559 price movement is non-trivial.** From the fee market tests, a block at 75% capacity (above the 50% target) raises the price from 30,000,000,000 to 30,312,500,000 fri — a ~1% jump per block. Under sustained congestion the price compounds every block.

```rust
// crates/apollo_consensus_orchestrator/src/fee_market/mod.rs:128-129
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```

**The two `check_fee_bounds` calls therefore use different prices:**

| Stage | Gas price used | Source |
|---|---|---|
| Gateway `run_validate_entry_point` | `P_prev` (previous block) | `gateway_fixed_block_state_reader.get_block_info()` |
| Batcher blockifier execution | `P_next` (EIP-1559 adjusted) | `ProposeBlockInput.block_info` from consensus orchestrator |

### Impact Explanation

**Scenario A — price rises (P_next > P_prev):**
A transaction with `max_price_per_unit = M` where `P_prev ≤ M < P_next` passes gateway `check_fee_bounds` (M ≥ P_prev) and is admitted to the mempool. At batcher execution, `check_fee_bounds` fails (M < P_next), the transaction is dropped as a `TransactionPreValidationError`, and is never included in any block. The gateway has accepted an invalid transaction.

**Scenario B — price falls (P_next < P_prev):**
A transaction with `max_price_per_unit = M` where `P_next ≤ M < P_prev` fails gateway `check_fee_bounds` (M < P_prev) and is rejected. The transaction would have passed at batcher execution (M ≥ P_next). The gateway has rejected a valid transaction.

Both scenarios match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

The L2 gas price changes every block. Under normal network load (blocks consistently above or below the 50% gas target), the price drifts monotonically, making Scenario A or B persistent across many consecutive blocks. Any user submitting a transaction priced near the current block's gas price will be affected. No special privileges or adversarial setup are required — ordinary transaction submission triggers the bug.

### Recommendation

In `run_validate_entry_point`, replace the previous block's gas prices with the next block's gas prices before constructing the `BlockContext`. The consensus orchestrator already computes `next_l2_gas_price` and stores it in the block header (`next_l2_gas_price` field in the protobuf header). The gateway should read this field (as the TODO comment at line 229 already notes) and apply it to all three gas price dimensions (L1, L1-data, L2) when building the block context for admission validation.

### Proof of Concept

1. Previous block L2 gas price: `P_prev = 30_000_000_000` fri (30 Gwei).
2. The block was 75% full → EIP-1559 raises the next block price to `P_next = 30_312_500_000` fri (confirmed by the fee market snapshot test).
3. User submits an invoke V3 transaction with `l2_gas.max_price_per_unit = 30_100_000_000`.
4. **Gateway `run_validate_entry_point`**: block context carries `l2_gas_price = 30_000_000_000`; `check_fee_bounds` sees `30_100_000_000 ≥ 30_000_000_000` → **PASS**. Transaction is admitted to the mempool.
5. **Batcher execution**: block context carries `l2_gas_price = 30_312_500_000`; `check_fee_bounds` sees `30_100_000_000 < 30_312_500_000` → **FAIL** (`TransactionPreValidationError::TransactionFeeError(InsufficientResourceBounds)`). Transaction is dropped without execution.
6. The user's transaction was accepted by the gateway, consumed a mempool slot, and was silently discarded at sequencing time — a wrong admission decision.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
        }
    }
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-139)
```rust
pub fn calculate_next_base_gas_price(
    price: GasPrice,
    gas_used: GasAmount,
    gas_target: GasAmount,
    min_gas_price: GasPrice,
) -> GasPrice {
    let versioned_constants = VersionedConstants::latest_constants();
    assert!(
        gas_target < versioned_constants.max_block_size,
        "Gas target must be lower than max block size."
    );
    assert!(gas_target.0 > 0, "Gas target must be greater than zero.");
    assert!(
        versioned_constants.gas_price_max_change_denominator > 0,
        "Denominator constant must be greater than zero."
    );

    // If the current price is below the minimum, apply a gradual adjustment and return early.
    // This allows the price to increase by at most 1/MIN_GAS_PRICE_INCREASE_DENOMINATOR per block.
    if price < min_gas_price {
        let max_increase = price.0 / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let adjusted = price.0 + max_increase;
        // Cap at min_gas_price to avoid overshooting
        let adjusted_price = adjusted.min(min_gas_price.0);
        info!(
            "Fee Market: Price {} below minimum gas price {}, adjusted price: {} )",
            price.0, min_gas_price.0, adjusted_price
        );
        return GasPrice(adjusted_price);
    }

    // Use U256 to avoid overflow, as multiplying a u128 by a u64 remains within U256 bounds.
    let gas_delta = U256::from(gas_used.0.abs_diff(gas_target.0));
    let gas_target_u256 = U256::from(gas_target.0);
    let price_u256 = U256::from(price.0);

    // Calculate price change by multiplying first, then dividing. This avoids the precision loss
    // that occurs when dividing before multiplying.
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

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
