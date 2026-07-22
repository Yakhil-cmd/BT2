### Title
Gateway L2 Gas Price Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Incorrect Admission and Rejection Decisions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validator checks a transaction's `max_price_per_unit` against the **current committed block's** `l2_gas_price`, but the batcher executes the transaction in the **next** block whose L2 gas price is `next_l2_gas_price` — a distinct EIP-1559-adjusted value stored in the same block header. A developer TODO comment in the code explicitly acknowledges this discrepancy. The result is that the gateway systematically admits transactions that will fail at execution (when prices are rising) and rejects transactions that would succeed (when prices are falling).

### Finding Description

**The two-price invariant in the block header**

Every committed block header carries two distinct L2 gas price fields:

- `l2_gas_price` — the price at which transactions in *that* block were charged.
- `next_l2_gas_price` — the EIP-1559-adjusted price for the *next* block, computed from `l2_gas_consumed` vs `gas_target`. [1](#0-0) [2](#0-1) 

**What the gateway reads**

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` by reading `block_header.l2_gas_price.price_in_fri` — the current block's price — and does **not** read `next_l2_gas_price`: [3](#0-2) 

**The admission check uses the wrong field**

`StatefulTransactionValidator::validate_resource_bounds` calls `get_block_info()` and extracts `strk_gas_prices.l2_gas_price`. The developer TODO comment directly acknowledges the bug:

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
``` [4](#0-3) 

The threshold check then enforces `tx.max_price_per_unit >= min_gas_price_percentage% * current_block.l2_gas_price`: [5](#0-4) 

**The blockifier validation in the gateway also uses the wrong price**

`run_validate_entry_point` builds a `BlockContext` from the same `get_block_info()` call (only incrementing `block_number`, not updating gas prices), so `check_fee_bounds` inside `perform_pre_validation_stage` also compares against `current_block.l2_gas_price`: [6](#0-5) 

**What the batcher uses**

The batcher builds its `BlockInfo` from the committed block header and uses `next_l2_gas_price` (via `calculate_next_l2_gas_price_for_fin`) as the L2 gas price for the new block being built: [7](#0-6) [8](#0-7) 

**The price divergence**

`calculate_next_base_gas_price` adjusts the price by up to `price / gas_price_max_change_denominator` per block (denominator = 48, ≈ 2%): [9](#0-8) 

With `gas_price_max_change_denominator = 48` from the versioned constants: [10](#0-9) 

### Impact Explanation

**Case 1 — Rising prices (full blocks, `next_l2_gas_price > current_block.l2_gas_price`):**

A transaction with `max_price_per_unit = P` where `current_block.l2_gas_price ≤ P < next_l2_gas_price` passes the gateway check (threshold = `min_gas_price_percentage% * current_block.l2_gas_price`) but fails at execution with `MaxGasPriceTooLow`. The gateway admits an invalid transaction.

**Case 2 — Falling prices (empty blocks, `next_l2_gas_price < current_block.l2_gas_price`):**

A transaction with `max_price_per_unit = P` where `next_l2_gas_price ≤ P < threshold` is rejected by the gateway even though it would succeed at execution. The gateway rejects a valid transaction.

Both cases match the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

The trigger is fully unprivileged: any user submitting a V3 (`AllResources`) transaction with `max_price_per_unit` in the divergence window is affected. The window is up to ~2% of the current price per block and is systematic during any sustained period of above- or below-target gas usage.

### Likelihood Explanation

The EIP-1559 mechanism is designed to keep blocks near the gas target. Any sustained deviation (busy or idle network) causes `next_l2_gas_price` to diverge from `current_block.l2_gas_price` by up to 2% per block. During normal mainnet operation with variable load, this divergence is continuously present. The `min_gas_price_percentage` default is 100, meaning the threshold equals the current block price exactly — the full divergence window is exposed.

### Recommendation

Replace the `get_block_info()` call in `validate_resource_bounds` with a read of `next_l2_gas_price` from the block header, as the TODO comment already prescribes:

```rust
// In validate_resource_bounds:
let next_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method to add
    .await?;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_l2_gas_price,
)?;
```

Extend `GatewayFixedBlockStateReader` to expose `next_l2_gas_price` from `BlockHeaderWithoutHash`, and apply the same fix to the `BlockContext` constructed in `run_validate_entry_point` so that `check_fee_bounds` also uses the correct price.

### Proof of Concept

1. Observe the latest committed block N with `l2_gas_price = P` and `next_l2_gas_price = P' = P * (1 + gas_delta / (gas_target * 48))` where `gas_delta > 0` (block was above target).

2. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P` (exactly at the gateway threshold when `min_gas_price_percentage = 100`).

3. Gateway `validate_resource_bounds`: `P >= 100% * P` → **PASS**.

4. Gateway `run_validate_entry_point` → `check_fee_bounds`: block context uses `P` → **PASS**.

5. Transaction enters mempool and is included in block N+1 by the batcher, which uses `P'` as the L2 gas price.

6. Batcher `check_fee_bounds`: `P < P'` → **FAIL** with `MaxGasPriceTooLow`.

7. Transaction is reverted; the user pays the revert fee despite the gateway having accepted the transaction as valid. [11](#0-10) [12](#0-11) [13](#0-12)

### Citations

**File:** crates/starknet_api/src/block.rs (L237-239)
```rust
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_storage/src/header.rs (L84-89)
```rust
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L30-57)
```rust
    async fn get_block_info_from_sync_client(&self) -> StarknetResult<BlockInfo> {
        let block = self.state_sync_client.get_block(self.block_number).await.map_err(|e| {
            StarknetError::internal_with_logging("Failed to get latest block info", e)
        })?;

        let block_header = block.block_header_without_hash;
        let block_info = BlockInfo {
            block_number: block_header.block_number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_wei.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_wei.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_wei.try_into()?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
            },
            use_kzg_da: block_header.l1_da_mode.is_use_kzg_da(),
            starknet_version: block_header.starknet_version,
        };

        Ok(block_info)
    }
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L322-330)
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-140)
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
}
```

**File:** crates/apollo_consensus_orchestrator/src/build_proposal.rs (L326-338)
```rust
                let next_l2_gas_price = calculate_next_l2_gas_price_for_fin(
                    args.l2_gas_price,
                    args.build_param.height,
                    info.l2_gas_used,
                    args.override_l2_gas_price_fri,
                    &args.min_l2_gas_price_per_height,
                    args.fee_actual,
                );
                let fin_payload = ProposalFinPayload {
                    commitment_parts: CommitmentParts::from(&info),
                    l2_gas_info: L2GasInfo {
                        next_l2_gas_price_fri: next_l2_gas_price,
                        l2_gas_used: info.l2_gas_used,
```

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_2.json (L1-9)
```json
{
    "fee_proposal_margin_ppt": 2,
    "fee_proposal_window_size": 10,
    "gas_price_max_change_denominator": 48,
    "gas_target": 1500000000,
    "max_block_size": 5800000000,
    "min_gas_price": "0x1dcd65000",
    "l1_gas_price_margin_percent": 10
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
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
