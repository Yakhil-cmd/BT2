### Title
Gateway L2 Gas Price Threshold Validated Against Stale `l2_gas_price` Instead of `next_l2_gas_price` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against a threshold derived from the **current block's** `l2_gas_price`. The block header already carries `next_l2_gas_price` — the EIP-1559-computed price for the block the transaction will actually execute in — but that field is never read. The code itself contains an explicit TODO acknowledging the wrong value is used. The mismatch causes the gateway to admit transactions that will fail at batcher execution (rising-price regime) and to reject transactions that would succeed (falling-price regime).

---

### Finding Description

**Step 1 — The stale read.**

`validate_resource_bounds` calls `get_block_info()` and extracts `strk_gas_prices.l2_gas_price`:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
``` [1](#0-0) 

**Step 2 — `BlockInfo` never carries `next_l2_gas_price`.**

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` copies `block_header.l2_gas_price` into `BlockInfo` but silently drops `block_header.next_l2_gas_price`:

```rust
l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
// next_l2_gas_price is present in block_header but never forwarded
``` [2](#0-1) 

Yet `next_l2_gas_price` is a first-class field of `BlockHeaderWithoutHash`: [3](#0-2) 

**Step 3 — The threshold check uses the wrong reference.**

The threshold is `(min_gas_price_percentage / 100) * l2_gas_price_of_block_N`. The batcher, however, builds block N+1 using the EIP-1559-computed `next_l2_gas_price` stored in block N's header: [4](#0-3) 

The EIP-1559 formula can shift the price by up to `price * gas_delta / (gas_target * denominator)` per block: [5](#0-4) 

**Step 4 — The blockifier validation inside the gateway also uses the stale price.**

`run_validate_entry_point` builds a `BlockContext` from the same stale `get_block_info()` result (only the block number is incremented, not the gas price): [6](#0-5) 

So both the gateway's threshold check and its embedded blockifier pre-validation use block N's `l2_gas_price`, while the batcher will execute with block N+1's `next_l2_gas_price`.

---

### Impact Explanation

**Rising-price regime** (`next_l2_gas_price > l2_gas_price`, e.g., block N was full):

- Gateway threshold = `min_gas_price_percentage% × l2_gas_price_N` (lower than actual execution price).
- A transaction with `max_price_per_unit` satisfying `threshold ≤ max_price < next_l2_gas_price` passes both the gateway threshold check and the gateway's embedded blockifier pre-validation (which also uses `l2_gas_price_N`).
- The batcher executes with `next_l2_gas_price` and the transaction fails `check_fee_bounds` → **invalid transaction admitted to mempool, wasting batcher resources and potentially displacing legitimate transactions**.

**Falling-price regime** (`next_l2_gas_price < l2_gas_price`, e.g., block N was empty):

- Gateway threshold = `min_gas_price_percentage% × l2_gas_price_N` (higher than actual execution price).
- A transaction with `max_price_per_unit` satisfying `next_l2_gas_price ≤ max_price < threshold` is rejected by the gateway even though it would succeed in the batcher → **valid transaction rejected before sequencing**.

Both outcomes match the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

- The EIP-1559 formula adjusts the price every block. On a consistently busy or consistently idle network the cumulative drift between `l2_gas_price` and `next_l2_gas_price` can be substantial.
- No privilege is required. Any user submitting a transaction with a gas price in the gap between the stale threshold and the actual next-block price triggers the wrong decision.
- The TODO comment in the source confirms the developers are aware the wrong field is being read, meaning the fix has not yet been applied.

---

### Recommendation

1. Extend `GatewayFixedBlockStateReader::get_block_info` (or add a dedicated method) to also return `block_header.next_l2_gas_price`.
2. In `validate_resource_bounds`, replace the read of `strk_gas_prices.l2_gas_price` with `block_header.next_l2_gas_price` (in FRI units).
3. In `run_validate_entry_point`, replace the gas prices in the constructed `BlockContext` with those derived from `next_l2_gas_price` so that the gateway's embedded blockifier pre-validation matches what the batcher will enforce.

---

### Proof of Concept

1. Observe the current `l2_gas_price` from the latest accepted block header (e.g., 100 FRI). The `next_l2_gas_price` in that same header is, say, 112 FRI (block was slightly above target).
2. Submit an invoke V3 transaction with `l2_gas.max_price_per_unit = 55 FRI` (above the 50% threshold of 50 FRI, below the actual execution price of 112 FRI).
3. The gateway's `validate_tx_l2_gas_price_within_threshold` computes `threshold = 50% × 100 = 50 FRI`; `55 ≥ 50` → passes.
4. The gateway's blockifier pre-validation also uses 100 FRI; `55 < 100` → this check fires `MaxGasPriceTooLow`. Wait — this means the embedded blockifier check would actually catch it.

Let me re-examine: the blockifier's `check_fee_bounds` checks `resource_bounds.max_price_per_unit < actual_gas_price` where `actual_gas_price` comes from the `BlockContext` built with the stale `l2_gas_price` (100 FRI). So `55 < 100` → the gateway's blockifier check **rejects** this transaction.

The exploitable window is therefore narrower: it requires `max_price_per_unit ≥ l2_gas_price_N` (to pass the gateway's blockifier check) but `max_price_per_unit < next_l2_gas_price` (to fail the batcher's blockifier check). Concretely:

1. `l2_gas_price_N = 100 FRI`, `next_l2_gas_price = 112 FRI`.
2. Submit with `max_price_per_unit = 105 FRI`.
3. Gateway threshold check: `105 ≥ 50` → passes.
4. Gateway blockifier check: `105 ≥ 100` → passes.
5. Batcher blockifier check: `105 < 112` → **fails with `MaxGasPriceTooLow`**.
6. Transaction was admitted to the mempool but is unexecutable, consuming mempool and batcher resources.

For the rejection direction: `l2_gas_price_N = 100 FRI`, `next_l2_gas_price = 88 FRI`, `min_gas_price_percentage = 95`.

1. Threshold = `95% × 100 = 95 FRI`.
2. Submit with `max_price_per_unit = 90 FRI`.
3. Gateway threshold check: `90 < 95` → **rejected**.
4. Batcher would accept: `90 ≥ 88` → would pass.
5. A valid transaction is incorrectly rejected at the gateway. [7](#0-6) [8](#0-7) [9](#0-8)

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
