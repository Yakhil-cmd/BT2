### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` validates a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price` field, but the correct reference price is `next_l2_gas_price` — the EIP-1559-computed price that will govern the block being built. The code itself carries a `TODO` acknowledging the wrong field is used. Because `next_l2_gas_price` is never exposed through `GatewayFixedBlockStateReader`, the stale price is structurally baked in.

### Finding Description

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

- `l2_gas_price` — the price that was in effect **for the block that was just committed** (used to compute fees for transactions already in that block).
- `next_l2_gas_price` — the EIP-1559-adjusted price **for the next block** (computed from the committed block's gas usage via `calculate_next_base_gas_price`). [1](#0-0) 

The gateway's stateful validator calls `validate_resource_bounds`, which fetches `BlockInfo` from `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`. That function maps `block_header.l2_gas_price.price_in_fri` into `BlockInfo.strk_gas_prices.l2_gas_price` and **silently drops** `block_header.next_l2_gas_price`: [2](#0-1) 

`validate_resource_bounds` then reads the stale field and the developer-acknowledged TODO confirms the wrong value is being used: [3](#0-2) 

The threshold check compares the transaction's `max_price_per_unit` against `min_gas_price_percentage × previous_block_l2_gas_price`: [4](#0-3) 

The consensus orchestrator computes `next_l2_gas_price` via EIP-1559 and stores it in the block header: [5](#0-4) [6](#0-5) 

When the network is under sustained load, `next_l2_gas_price` rises above `l2_gas_price` each block. The gateway's threshold is anchored to the lower stale value, so transactions whose `max_price_per_unit` falls in the gap `[min_pct × l2_gas_price, next_l2_gas_price)` pass gateway admission. Conversely, when load drops, `next_l2_gas_price < l2_gas_price`, and the threshold is inflated, causing the gateway to reject transactions that are perfectly valid for the next block.

### Impact Explanation

**Accepts invalid transactions (high load):** A transaction with `max_price_per_unit = P` where `min_pct × l2_gas_price ≤ P < next_l2_gas_price` passes `validate_resource_bounds` and the gateway's blockifier validation (which also uses the stale `l2_gas_price`), enters the mempool, and is later rejected by the batcher's `check_fee_bounds` when it executes against the actual next-block price. This pollutes the mempool with transactions that cannot be sequenced.

**Rejects valid transactions (low load):** A transaction with `max_price_per_unit = P` where `min_pct × next_l2_gas_price ≤ P < min_pct × l2_gas_price` is rejected at the gateway even though it can pay the actual next-block price. This is a definitive wrong admission decision.

Both directions match **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The EIP-1559 formula adjusts the price every block based on gas usage. Any sustained period of above-target or below-target block utilization produces a persistent gap between `l2_gas_price` and `next_l2_gas_price`. This is a normal operating condition, not an edge case. Any unprivileged user submitting a V3 (`AllResources`) transaction is affected.

### Recommendation

1. Extend `GatewayFixedBlockStateReader::get_block_info` (or add a new method) to return `next_l2_gas_price` from `BlockHeaderWithoutHash`.
2. In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, propagate `block_header.next_l2_gas_price`.
3. In `validate_resource_bounds`, replace `previous_block_l2_gas_price` with the `next_l2_gas_price` read from the block header — exactly as the existing TODO comment directs.

### Proof of Concept

1. Observe a sequence of blocks where gas usage consistently exceeds `gas_target`. After several blocks, `next_l2_gas_price` will be measurably higher than `l2_gas_price` (EIP-1559 raises it by up to `1/gas_price_max_change_denominator` per block).
2. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = l2_gas_price` (the stale value). With `min_gas_price_percentage = 100`, the threshold equals `l2_gas_price`, so the transaction passes `validate_resource_bounds`.
3. The gateway's blockifier validation (`run_validate_entry_point`) also uses `l2_gas_price` (same stale `BlockInfo`), so `check_fee_bounds` passes there too.
4. The transaction enters the mempool.
5. When the batcher builds the next block using `next_l2_gas_price` as the block's L2 gas price, `check_fee_bounds` finds `max_price_per_unit < actual_gas_price` and the transaction fails — it was admitted by the gateway but cannot be sequenced. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** crates/starknet_api/src/block.rs (L231-248)
```rust
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct BlockHeaderWithoutHash {
    pub parent_hash: BlockHash,
    pub block_number: BlockNumber,
    pub l1_gas_price: GasPricePerToken,
    pub l1_data_gas_price: GasPricePerToken,
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
    pub state_root: GlobalRoot,
    pub sequencer: SequencerContractAddress,
    pub timestamp: BlockTimestamp,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub starknet_version: StarknetVersion,
    // TODO(AndrewL): Add this field into the block hash.
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
}
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L396-412)
```rust
        let l2_gas_price = cende_block_info.gas_prices.l2_gas_price_per_token();
        let sequencer = SequencerContractAddress(init.builder);

        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
            timestamp: BlockTimestamp(init.timestamp),
            l1_da_mode: init.l1_da_mode,
            fee_proposal_fri: init.fee_proposal_fri,
            // TODO(guy.f): Figure out where/if to get the values below from and fill them.
            ..Default::default()
        };
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

**File:** crates/apollo_storage/src/header.rs (L87-90)
```rust
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
```
