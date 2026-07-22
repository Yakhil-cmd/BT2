### Title
Gateway `validate_resource_bounds` uses stale previous-block L2 gas price instead of next-block price, causing incorrect admission/rejection of v3 transactions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful validator checks a v3 transaction's `max_price_per_unit` for L2 gas against the **previous block's** L2 gas price. The batcher executes those same transactions against the **next block's** L2 gas price, which is computed via an EIP-1559-like mechanism and can differ materially from the previous block's price. This mismatch causes the gateway to admit transactions that will fail the blockifier's fee check (when the price is rising) or to reject transactions that would succeed in the batcher (when the price is falling). The code itself carries a developer TODO acknowledging the wrong value is used.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price from the **latest committed block** and uses it as the reference for the admission threshold:

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

`validate_tx_l2_gas_price_within_threshold` then rejects any `AllResources` transaction whose `l2_gas.max_price_per_unit` is below `min_gas_price_percentage% × previous_block_l2_gas_price`: [2](#0-1) 

The `run_validate_entry_point` function also builds its `BlockContext` from the same previous-block info (only incrementing the block number, not the gas prices): [3](#0-2) 

The batcher, however, executes transactions against the **next block's** L2 gas price, which is computed by `calculate_next_base_gas_price` — an EIP-1559-style formula that adjusts the price up or down based on how much gas the previous block consumed relative to the target: [4](#0-3) 

The blockifier's `check_fee_bounds` (called during `perform_pre_validation_stage`) enforces that `tx.max_price_per_unit >= actual_block_l2_gas_price` using the **current block's** gas prices: [5](#0-4) 

The two reference prices are therefore structurally different:

| Stage | L2 gas price used |
|---|---|
| Gateway `validate_resource_bounds` | `previous_block.l2_gas_price` (stale) |
| Batcher `check_fee_bounds` | `next_block.l2_gas_price` (current) |

**Scenario A — price rising (high congestion, `gas_used > gas_target`):**
`next_block_price > previous_block_price`. A transaction with `tx_l2_gas_price` in the range `[min_gas_price_percentage% × previous_block_price, next_block_price)` passes the gateway threshold but fails the blockifier's strict check. The gateway admits a transaction that the batcher will reject.

**Scenario B — price falling (low congestion, `gas_used < gas_target`):**
`next_block_price < previous_block_price`. A transaction with `tx_l2_gas_price` in the range `[next_block_price, min_gas_price_percentage% × previous_block_price)` is rejected by the gateway even though the batcher would accept it. A valid transaction is denied admission.

The `GatewayFixedBlockSyncStateClient` caches the block info in a `OnceCell`, so the stale price is frozen for the entire lifetime of the validator instance: [6](#0-5) 

---

### Impact Explanation

**Scenario A** — the gateway admits v3 transactions that carry an L2 gas `max_price_per_unit` below the actual next-block price. These transactions enter the mempool and are handed to the batcher, where `check_fee_bounds` rejects them with `TransactionPreValidationError::InsufficientResourceBounds`. The batcher discards them without including them in a block. An attacker can deliberately craft transactions that pass gateway admission but are guaranteed to fail execution, polluting the mempool and wasting batcher CPU.

**Scenario B** — the gateway rejects v3 transactions that are fully valid for the next block. A user who sets `max_price_per_unit` to exactly the next-block price (which is lower than the previous-block price during a low-congestion period) receives a `GAS_PRICE_TOO_LOW` error and cannot submit their transaction, even though the batcher would accept it. This is a denial-of-service against legitimate users during any period of falling gas prices.

Both outcomes fall squarely within: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The L2 gas price changes every block via `calculate_next_base_gas_price`. At 75% block utilisation the price rises ~1.5% per block; at 25% utilisation it falls ~1.5% per block. With `min_gas_price_percentage = 100` (the default), the admission window and the execution window diverge by that percentage every block. The discrepancy is therefore present in every non-stable-utilisation block, which is the common case under real network load. [7](#0-6) 

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` with the **next block's** L2 gas price. The next-block price is already stored in the committed block header as `next_l2_gas_price` (populated by `update_state_sync_with_new_block`): [8](#0-7) 

`GatewayFixedBlockStateReader::get_block_info` should be extended (or a new method added) to return `next_l2_gas_price` from the block header, and `validate_resource_bounds` should use that value instead of `l2_gas_price`. This directly resolves the developer TODO at line 229.

---

### Proof of Concept

1. Observe the current committed block has `l2_gas_price = P` and was built at 75% utilisation, so `next_block_price ≈ P × 1.015`.
2. Submit a v3 `InvokeTransaction` with `AllResources { l2_gas: { max_price_per_unit: P } }` (i.e., exactly the previous-block price, which is below the next-block price).
3. With `min_gas_price_percentage = 100`, the gateway threshold is `P`. The transaction satisfies `P >= P` and is admitted.
4. The batcher builds the next block with `l2_gas_price = P × 1.015`. `check_fee_bounds` evaluates `P < P × 1.015` and raises `MaxGasPriceTooLow`, rejecting the transaction.
5. The transaction was admitted to the mempool but will never be sequenced.

Conversely, for Scenario B: submit the same transaction during a low-congestion period where `next_block_price = P × 0.985`. The gateway rejects it with `GAS_PRICE_TOO_LOW` (threshold = `P`, tx price = `P × 0.985`), even though the batcher would accept it. [9](#0-8) [10](#0-9) [4](#0-3)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-450)
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
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L62-67)
```rust
    async fn get_block_info(&self) -> StarknetResult<BlockInfo> {
        self.block_info_cache
            .get_or_try_init(|| self.get_block_info_from_sync_client())
            .await
            .cloned()
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-406)
```rust
        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
```
