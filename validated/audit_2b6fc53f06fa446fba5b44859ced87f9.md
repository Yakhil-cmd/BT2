### Title
Gateway L2 Gas Price Validation Uses Stale Current-Block Price Instead of Next-Block Price, Admitting Transactions That Will Fail Execution — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks the transaction's L2 gas price against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next block** at `next_l2_gas_price` (the EIP-1559 adjusted price stored in the block header). When the next block's price is higher than the current block's price (due to high gas usage), transactions with gas prices between the two values pass gateway admission but fail during batcher execution with `MaxGasPriceTooLow`. The code itself carries a TODO acknowledging the wrong reference.

### Finding Description

In `validate_resource_bounds`, the code reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` — the **current block's** L2 gas price — as the threshold reference: [1](#0-0) 

The comment `// TODO(Arni): getnext_l2_gas_price from the block header.` explicitly acknowledges that the correct reference is `next_l2_gas_price`, not `l2_gas_price`.

The root cause is structural: `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` maps `block_header.l2_gas_price.price_in_fri` into `BlockInfo` but silently drops `block_header.next_l2_gas_price`: [2](#0-1) 

The `next_l2_gas_price` field exists in `BlockHeaderWithoutHash` and is stored in `StorageBlockHeader`: [3](#0-2) 

It is also written into the block header by the consensus orchestrator: [4](#0-3) 

The same stale-price problem propagates into `run_validate_entry_point`, which advances the block number to N+1 but leaves gas prices at block N's values: [5](#0-4) 

So the blockifier validation inside the gateway runs with block-number N+1 but gas prices from block N, while the batcher will execute the transaction at block N+1's actual price (`next_l2_gas_price` from block N's header).

### Impact Explanation

When the EIP-1559 mechanism raises the next block's L2 gas price (high gas usage in block N), a transaction with `l2_gas.max_price_per_unit = P_current` will:

1. Pass `validate_resource_bounds`: `P_current >= threshold × P_current` ✓
2. Pass the gateway's blockifier `check_fee_bounds` (also uses `P_current`) ✓
3. Be admitted to the mempool ✓
4. Fail in the batcher's `perform_pre_validation_stage` with `MaxGasPriceTooLow` because the batcher uses `P_next > P_current` ✗ [6](#0-5) 

The symmetric case (price decreasing) causes valid transactions to be incorrectly rejected at the gateway. Both outcomes match the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The EIP-1559 formula adjusts the price every block whenever gas usage deviates from the target. The maximum per-block change is `price / gas_price_max_change_denominator` (denominator ≈ 333, so ≈ 0.3% per block): [7](#0-6) 

The discrepancy is therefore small per block but **systematic**: it is present on every block where gas usage differs from the target, which is the normal operating condition under any real load. Any unprivileged user submitting a transaction at exactly the current block's price triggers the issue.

### Recommendation

1. Add `next_l2_gas_price` to the `BlockInfo` struct (or expose it as a separate field on `GatewayFixedBlockStateReader`).
2. In `get_block_info_from_sync_client`, map `block_header.next_l2_gas_price` into the returned value.
3. In `validate_resource_bounds`, replace `block_info.gas_prices.strk_gas_prices.l2_gas_price` with `next_l2_gas_price`.
4. In `run_validate_entry_point`, update the gas prices in `block_info` to `next_l2_gas_price` before constructing the `BlockContext`, so the blockifier validation inside the gateway is consistent with what the batcher will enforce.

### Proof of Concept

```
Block N:  l2_gas_price = 1000 fri,  next_l2_gas_price = 1003 fri  (high usage)

Attacker submits invoke tx with l2_gas.max_price_per_unit = 1000 fri.

Gateway validate_resource_bounds:
  threshold = 100% × 1000 = 1000
  1000 >= 1000  → PASS ✓

Gateway blockifier validation (block_info uses 1000 fri):
  check_fee_bounds: 1000 >= 1000  → PASS ✓

Transaction admitted to mempool.

Batcher builds block N+1 with l2_gas_price = 1003 fri:
  check_fee_bounds: 1000 < 1003  → MaxGasPriceTooLow ✗

Transaction rejected during pre-validation; mempool slot consumed,
user's transaction permanently stuck.
```

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

**File:** crates/apollo_storage/src/header.rs (L88-90)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L440-449)
```rust
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
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-115)
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
```
