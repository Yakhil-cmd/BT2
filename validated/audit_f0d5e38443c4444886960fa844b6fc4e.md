### Title
Gateway stateful validator uses current block's `l2_gas_price` instead of `next_l2_gas_price` for resource-bound admission check — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` (the **current** block's L2 gas price) as the reference price for the admission threshold, but the transaction will be executed in the **next** block whose L2 gas price is `block_header.next_l2_gas_price`. The two values diverge whenever the EIP-1559 fee market adjusts the price between blocks. The code itself carries a `TODO` acknowledging the wrong field is used.

### Finding Description

In `validate_resource_bounds` the gateway fetches the latest committed block's `BlockInfo` and extracts the STRK L2 gas price:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices   // ← current block's price vector
    .l2_gas_price;     // ← current block's L2 gas price
``` [1](#0-0) 

This value is then used to compute the minimum acceptable L2 gas price for the incoming transaction:

```rust
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,   // ← wrong reference price
)?;
``` [2](#0-1) 

The threshold is `min_gas_price_percentage * previous_block_l2_gas_price / 100`: [3](#0-2) 

The block header, however, carries a **separate** `next_l2_gas_price` field that encodes the L2 gas price the sequencer will use for the **next** block (the block the transaction will actually land in). This field is present in `BlockHeaderWithoutHash`: [4](#0-3) 

and in the feeder-gateway block object: [5](#0-4) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` converts the block header into a `BlockInfo` but silently drops `next_l2_gas_price`, mapping only `l2_gas_price.price_in_fri` into `strk_gas_prices.l2_gas_price`: [6](#0-5) 

The same `get_block_info()` call in `run_validate_entry_point` also builds the blockifier's `BlockContext` from the same stale price, so the blockifier pre-validation (`check_fee_bounds`) is equally misaligned with the actual execution block: [7](#0-6) 

### Impact Explanation

Two divergent scenarios arise whenever `next_l2_gas_price ≠ current_block.l2_gas_price`:

**Scenario A – price rising (network under load):**
`next_l2_gas_price > current_block.l2_gas_price`. The gateway threshold is computed from the lower current price, so transactions whose `max_price_per_unit` falls in `[threshold(current), threshold(next))` pass gateway admission and enter the mempool. When the batcher includes them in the next block (which uses `next_l2_gas_price`), `check_fee_bounds` rejects them. The gateway has admitted transactions that are invalid for the block they will be sequenced into.

**Scenario B – price falling (network idle):**
`next_l2_gas_price < current_block.l2_gas_price`. The gateway threshold is computed from the higher current price, so transactions whose `max_price_per_unit` falls in `[threshold(next), threshold(current))` are rejected at the gateway even though they would satisfy the actual next-block price. Valid transactions are denied admission.

Both outcomes match the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 L2 fee market adjusts `next_l2_gas_price` every block based on gas consumption. Any block that is not exactly at the target utilisation produces a `next_l2_gas_price` that differs from the current block's `l2_gas_price`. This is the normal operating condition of the network. No privileged access is required; any user submitting a V3 (`AllResources`) transaction with a gas price in the divergence band triggers the misbehaviour.

### Recommendation

1. Extend `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` (or introduce a separate accessor) to surface `block_header.next_l2_gas_price` alongside the existing `BlockInfo`.
2. Replace the reference price in `validate_resource_bounds` with `next_l2_gas_price`:

```diff
-// TODO(Arni): getnext_l2_gas_price from the block header.
-let previous_block_l2_gas_price = self
+let next_block_l2_gas_price = self
     .gateway_fixed_block_state_reader
-    .get_block_info()
+    .get_next_l2_gas_price()   // new accessor returning next_l2_gas_price
     .await?
-    .gas_prices
-    .strk_gas_prices
-    .l2_gas_price;
 self.validate_tx_l2_gas_price_within_threshold(
     executable_tx.resource_bounds(),
-    previous_block_l2_gas_price,
+    next_block_l2_gas_price,
 )?;
```

3. Apply the same correction to the `BlockContext` gas prices used in `run_validate_entry_point` so that blockifier pre-validation is consistent with the actual execution block.

### Proof of Concept

1. Read the latest committed block header. Note `l2_gas_price.price_in_fri = P` and `next_l2_gas_price = P'` where `P' > P` (rising market).
2. Compute `threshold_current = min_gas_price_percentage * P / 100` and `threshold_next = min_gas_price_percentage * P' / 100`.
3. Submit a V3 Invoke transaction with `resource_bounds.l2_gas.max_price_per_unit = threshold_current` (i.e., exactly at the current threshold but below the next-block threshold).
4. The gateway's `validate_tx_l2_gas_price_within_threshold` compares against `threshold_current` → **passes**, transaction enters the mempool.
5. When the batcher sequences the transaction into the next block (whose `l2_gas_price = P'`), `check_fee_bounds` compares `max_price_per_unit < P'` → **fails**, transaction is reverted or dropped.

The gateway has admitted a transaction that is invalid for the block it will be sequenced into, violating the admission invariant.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-236)
```rust
            // TODO(Arni): getnext_l2_gas_price from the block header.
            let previous_block_l2_gas_price = self
                .gateway_fixed_block_state_reader
                .get_block_info()
                .await?
                .gas_prices
                .strk_gas_prices
                .l2_gas_price;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L237-240)
```rust
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L366-383)
```rust
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
```

**File:** crates/starknet_api/src/block.rs (L1-1)
```rust
#[cfg(test)]
```

**File:** crates/apollo_starknet_client/src/reader/objects/block.rs (L86-90)
```rust
    // New fields in V0.14.0. Only returned by the feeder gateway when the request includes
    // `withFeeMarketInfo=true`.
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,

```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L36-57)
```rust
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
