### Title
Gateway L2 Gas Price Threshold Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Wrong Admission Decisions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a V3 transaction's `l2_gas.max_price_per_unit` against the **current block's** `l2_gas_price`, but the block the transaction will actually be executed in uses `next_l2_gas_price` (the EIP-1559-derived price stored in the same block header). The gateway therefore applies the wrong price reference, admitting transactions that will fail in the batcher when the price is rising, and rejecting valid transactions when the price is falling. A developer TODO in the source code explicitly acknowledges the correct field is `next_l2_gas_price`.

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` reads the L2 gas price from `GatewayFixedBlockStateReader::get_block_info()`:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates that field from `block_header.l2_gas_price.price_in_fri` — the **current** block's L2 gas price — and never reads `block_header.next_l2_gas_price`:

```rust
strk_gas_prices: GasPriceVector {
    ...
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

`next_l2_gas_price` is a separate field in the block header (EIP-1559 computed price for the **next** block): [3](#0-2) 

When the consensus orchestrator builds a new block it sets `l2_gas_price = sync_block.block_header_without_hash.next_l2_gas_price` and passes it as `l2_gas_price_fri` in `ProposalInit`, which becomes the L2 gas price for the block being sequenced: [4](#0-3) [5](#0-4) 

The gateway's `run_validate_entry_point` also uses the same stale `block_info` (only incrementing `block_number`, not updating gas prices), so both the pre-check and the blockifier validation inside the gateway use `l2_gas_price`, while the batcher uses `next_l2_gas_price`: [6](#0-5) 

### Impact Explanation

**False admission (price rising — `next_l2_gas_price > l2_gas_price`):**
A transaction with `max_price_per_unit` in the range `[threshold × l2_gas_price, next_l2_gas_price)` passes `validate_tx_l2_gas_price_within_threshold` and the gateway's blockifier validation, enters the mempool, but fails `check_fee_bounds` in the batcher's blockifier execution because the actual block price is `next_l2_gas_price`. The gateway has admitted an invalid transaction.

**False rejection (price falling — `next_l2_gas_price < l2_gas_price`):**
A transaction with `max_price_per_unit` in `[threshold × next_l2_gas_price, threshold × l2_gas_price)` is rejected by the gateway even though it would satisfy the batcher's price check. The gateway has rejected a valid transaction.

The EIP-1559 mechanism means the price changes every block proportional to gas usage, so the divergence between `l2_gas_price` and `next_l2_gas_price` is a normal, continuous condition — not an edge case.

### Likelihood Explanation

This triggers on every V3 (`AllResources`) transaction submitted when `next_l2_gas_price ≠ l2_gas_price`, which is the normal operating state. Any user submitting a V3 transaction with `max_price_per_unit` set to exactly the current block's price (a common pattern) will be affected when the price is rising. No special privileges are required.

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, expose `next_l2_gas_price` from the block header and use it in `validate_resource_bounds` instead of `l2_gas_price`. Alternatively, add a dedicated method to `GatewayFixedBlockStateReader` that returns `next_l2_gas_price` directly, and update `validate_resource_bounds` to call it:

```rust
// In get_block_info_from_sync_client or a new method:
let next_l2_gas_price = block_header.next_l2_gas_price; // already stored in header

// In validate_resource_bounds:
// TODO(Arni): getnext_l2_gas_price from the block header.  <-- resolve this TODO
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method
    .await?;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_block_l2_gas_price,
)?;
```

The same fix should be applied to `run_validate_entry_point`'s `block_info` construction so that the blockifier validation inside the gateway also uses `next_l2_gas_price` as the L2 gas price.

### Proof of Concept

1. Block N is finalized with `l2_gas_price = 10 Gwei` and `next_l2_gas_price = 12 Gwei` (block was full, price rose 20%).
2. User submits a V3 invoke transaction with `l2_gas.max_price_per_unit = 11 Gwei` and `min_gas_price_percentage = 100`.
3. Gateway calls `validate_resource_bounds`: threshold = `100% × 10 Gwei = 10 Gwei`; `11 Gwei ≥ 10 Gwei` → **passes**.
4. Gateway calls `run_validate_entry_point` with `block_info.gas_prices.l2_gas_price = 10 Gwei`; blockifier `check_fee_bounds` checks `11 Gwei ≥ 10 Gwei` → **passes**.
5. Transaction enters the mempool.
6. Batcher builds block N+1 with `l2_gas_price = next_l2_gas_price = 12 Gwei`.
7. Blockifier `check_fee_bounds` checks `11 Gwei ≥ 12 Gwei` → **fails** with `MaxGasPriceTooLow`.
8. The gateway admitted a transaction that the batcher cannot include. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-240)
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

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L1056-1059)
```rust
        self.l2_gas_price = max(
            sync_block.block_header_without_hash.next_l2_gas_price,
            VersionedConstants::latest_constants().min_gas_price,
        );
```

**File:** crates/apollo_consensus_orchestrator/src/build_proposal.rs (L177-177)
```rust
        l2_gas_price_fri: args.l2_gas_price,
```
