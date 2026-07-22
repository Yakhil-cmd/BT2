### Title
Gateway L2 Gas Price Threshold Checks Against Previous Block Instead of Next Block, Causing Incorrect Transaction Admission/Rejection — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` queries the **previous (latest committed) block's** L2 gas price from `gateway_fixed_block_state_reader` to enforce the minimum gas price threshold, but the correct reference is the **next block's** L2 gas price. A developer TODO comment in the code explicitly acknowledges this wrong source. This is the direct sequencer analog of the Size M-03 bug: both query the wrong contract/state source for a value used in an admission check, causing the check to produce incorrect results.

### Finding Description

In `validate_resource_bounds`, the gateway fetches the reference L2 gas price from `gateway_fixed_block_state_reader.get_block_info()`, which returns the **latest committed block's** info:

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

The `validate_tx_l2_gas_price_within_threshold` function then computes a threshold as `min_gas_price_percentage% × previous_block_l2_gas_price` and rejects any `AllResources` V3 transaction whose `l2_gas.max_price_per_unit` falls below it: [2](#0-1) 

The `GatewayFixedBlockSyncStateClient` that backs `gateway_fixed_block_state_reader` reads from `latest_block_number` — the last **committed** block, not the block being built: [3](#0-2) 

The `SyncStateReaderFactory` confirms both the blockifier state reader and the fixed-block reader are anchored to the same `latest_block_number`: [4](#0-3) 

Meanwhile, `run_validate_entry_point` increments only the **block number**, leaving the gas prices unchanged from the previous block: [5](#0-4) 

The batcher will execute the transaction with the **actual next block's** gas prices, which may differ from the previous block's prices. The gateway's threshold check and the batcher's execution context are therefore anchored to different price points.

### Impact Explanation

When L2 gas prices change between blocks (a normal occurrence):

1. **Gas price decreasing** (next block price < previous block price): A transaction whose `l2_gas.max_price_per_unit` satisfies `threshold(next) ≤ price < threshold(prev)` is **rejected by the gateway** even though it is valid for the next block. This is a denial-of-service against legitimate users submitting correctly-priced V3 transactions.

2. **Gas price increasing** (next block price > previous block price): A transaction whose `l2_gas.max_price_per_unit` satisfies `threshold(prev) ≤ price < threshold(next)` is **admitted by the gateway** even though it is underpriced relative to the next block's threshold. The batcher does not re-enforce this threshold, so the transaction executes, bypassing the spam-prevention gate.

Both outcomes match the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

L2 gas prices on Starknet are updated every block. Any block-to-block price movement — upward or downward — creates a window where the wrong threshold is applied. The magnitude of the error scales with `min_gas_price_percentage` and the size of the price change. The developer's own TODO comment confirms this is a known wrong-source issue awaiting a fix.

### Recommendation

Replace the previous block's L2 gas price with the **next block's** L2 gas price in `validate_resource_bounds`. Since the next block's price is determined by the sequencer before building the block, it should be passed into the gateway validator (e.g., via the block header of the pending block or a dedicated price oracle), matching the comment's intent:

```rust
// Instead of:
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;

// Use the next block's L2 gas price, e.g.:
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_block_l2_gas_price()  // new API
    .await?;
```

### Proof of Concept

Assume `min_gas_price_percentage = 50` and the previous block's STRK L2 gas price is `100 fri`. The threshold is `50 fri`.

A user submits a V3 `AllResources` transaction with `l2_gas.max_price_per_unit = 60 fri`. The gateway admits it (60 ≥ 50).

The sequencer then sets the next block's L2 gas price to `200 fri` (threshold = `100 fri`). The batcher executes the transaction at `200 fri` per unit — the transaction's declared max price of `60 fri` is below the block price, so the transaction is underpriced and should have been rejected at admission.

Conversely, if the previous block's price was `200 fri` (threshold = `100 fri`) and the next block's price drops to `100 fri` (threshold = `50 fri`), a user submitting a transaction with `l2_gas.max_price_per_unit = 70 fri` is rejected by the gateway (70 < 100) even though 70 ≥ 50 is valid for the next block.

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-57)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}

impl GatewayFixedBlockSyncStateClient {
    pub fn new(state_sync_client: SharedStateSyncClient, block_number: BlockNumber) -> Self {
        Self { state_sync_client, block_number, block_info_cache: OnceCell::new() }
    }

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

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L539-549)
```rust
        let blockifier_state_reader = SyncStateReader::from_number(
            self.shared_state_sync_client.clone(),
            self.class_manager_client.clone(),
            latest_block_number,
            self.runtime.clone(),
        );
        let gateway_fixed_block_sync_state_client = GatewayFixedBlockSyncStateClient::new(
            self.shared_state_sync_client.clone(),
            latest_block_number,
        );
        Ok((blockifier_state_reader.into(), gateway_fixed_block_sync_state_client.into()))
```
