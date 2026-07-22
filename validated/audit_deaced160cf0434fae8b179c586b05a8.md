### Title
Gateway Stateful Validator Uses Current Block's `l2_gas_price` Instead of `next_l2_gas_price` for Resource-Bounds Admission Check - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check compares a transaction's `max_price_per_unit` against the **current block's** L2 gas price (`strk_gas_prices.l2_gas_price`). The correct reference is `next_l2_gas_price` — the EIP-1559-derived price that will govern the block the transaction is actually included in. The code itself carries a `TODO` acknowledging this. The mismatch causes the gateway to admit transactions that will fail blockifier's `check_fee_bounds` (price rising) or reject transactions that are valid for the next block (price falling).

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads the reference price as:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the price **of the current (latest committed) block**:

```rust
strk_gas_prices: GasPriceVector {
    ...
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

The block header also carries a distinct `next_l2_gas_price` field — the EIP-1559 price computed for the **next** block:

```rust
pub next_l2_gas_price: GasPrice,
``` [3](#0-2) 

`next_l2_gas_price` is computed by `calculate_next_l2_gas_price_for_fin` and stored in `BlockHeaderWithoutHash` when a block is committed:

```rust
next_l2_gas_price: self.l2_gas_price,
``` [4](#0-3) 

The threshold check then uses the wrong reference:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...GAS_PRICE_TOO_LOW...) }
``` [5](#0-4) 

The blockifier's `check_fee_bounds` (executed later, during actual block building) compares against the **actual block's** gas price — which equals `next_l2_gas_price` of the previous block:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [6](#0-5) 

### Impact Explanation

**Price-rising scenario (EIP-1559 congestion):** `next_l2_gas_price > l2_gas_price`. The gateway threshold is computed from the lower current price, so transactions with `max_price_per_unit` in the range `[threshold_current, threshold_next)` pass gateway admission but fail blockifier's `check_fee_bounds` during execution. Invalid transactions are admitted to the mempool and waste block-building resources.

**Price-falling scenario:** `next_l2_gas_price < l2_gas_price`. The gateway threshold is computed from the higher current price, so transactions with `max_price_per_unit` in the range `[threshold_next, threshold_current)` are rejected by the gateway even though they would be valid for the next block. Valid transactions are incorrectly rejected before sequencing.

Both directions match the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The EIP-1559 L2 gas price adjusts every block based on gas usage. Any block with usage above or below the gas target causes `next_l2_gas_price ≠ l2_gas_price`. This is the normal operating condition, not an edge case. The discrepancy grows with sustained high or low usage. The `TODO` comment in the code confirms the developers are aware the wrong field is being used.

### Recommendation

Replace the `l2_gas_price` field read with `next_l2_gas_price` from the block header. This requires either:
1. Propagating `next_l2_gas_price` through `BlockInfo` (add a field), or
2. Exposing it separately from `GatewayFixedBlockStateReader::get_block_info`.

The `GatewayFixedBlockSyncStateClient` already has access to `block_header.next_l2_gas_price` from the `SyncBlock`; it just needs to be surfaced.

### Proof of Concept

1. Observe a sequence of blocks with above-target L2 gas usage so that `next_l2_gas_price > l2_gas_price` by, say, 10%.
2. Submit an `AllResources` V3 invoke transaction with `l2_gas.max_price_per_unit` set to exactly `l2_gas_price` (current block price).
3. The gateway's `validate_tx_l2_gas_price_within_threshold` computes `threshold = min_gas_price_percentage% * l2_gas_price` and passes the transaction (assuming `min_gas_price_percentage ≤ 100`).
4. The transaction enters the mempool and is picked up by the batcher.
5. Blockifier's `check_fee_bounds` compares `max_price_per_unit` against the actual block's gas price (`next_l2_gas_price`, which is 10% higher) and raises `MaxGasPriceTooLow`, causing the transaction to fail pre-validation — wasting a mempool slot and a block-building attempt. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L404-406)
```rust
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
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
