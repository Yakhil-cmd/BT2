I have enough information to write the finding. The key evidence is:

1. The `validate_resource_bounds` function has an explicit TODO acknowledging it uses the wrong price
2. The `run_validate_entry_point` also uses the same stale `block_info` gas prices
3. The `BlockHeaderWithoutHash` stores both `l2_gas_price` (current block) and `next_l2_gas_price` (for the next block)
4. The gateway reads only `l2_gas_price` from the previous block, not `next_l2_gas_price`

---

### Title
Gateway L2 Gas Price Admission Check Uses Previous Block's `l2_gas_price` Instead of `next_l2_gas_price` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful admission path validates a transaction's `max_price_per_unit` against the **previous block's `l2_gas_price`**, but the transaction will actually be executed in the **next block**, whose L2 gas price is `next_l2_gas_price` (computed via EIP-1559 from the previous block header). When the EIP-1559 formula raises the price between blocks, transactions whose `max_price_per_unit` falls in the gap `[next_l2_gas_price, l2_gas_price)` pass gateway admission but will fail `check_fee_bounds` during batcher execution. The code itself contains an unresolved TODO acknowledging the correct value to use.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` fetches the previous block's `BlockInfo` and reads `gas_prices.strk_gas_prices.l2_gas_price` as the reference price:

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

The same stale `block_info` is then forwarded into the blockifier's `check_fee_bounds` inside `run_validate_entry_point`. The block number is incremented, but the gas prices are **not** updated to the next block's prices:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
// gas_prices still reflect the previous block, not next_l2_gas_price
let block_context = BlockContext::new(block_info, ...);
``` [2](#0-1) 

The block header stores two distinct fields: `l2_gas_price` (the price used in the current block) and `next_l2_gas_price` (the EIP-1559-adjusted price that will govern the **next** block). The orchestrator writes `next_l2_gas_price: self.l2_gas_price` into the committed block header: [3](#0-2) 

The `StorageBlockHeader` and `BlockHeaderWithoutHash` both carry this separate `next_l2_gas_price` field: [4](#0-3) 

However, `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` only populates the `BlockInfo.gas_prices` from `block_header.l2_gas_price`, discarding `next_l2_gas_price` entirely: [5](#0-4) 

The EIP-1559 formula (`calculate_next_base_gas_price`) can raise the price by up to `price / gas_price_max_change_denominator` per block when the block is full: [6](#0-5) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

When the L2 gas price is rising (EIP-1559 increase due to high block utilization), a transaction with `max_price_per_unit` satisfying `l2_gas_price * min_gas_price_percentage% ≤ max_price_per_unit < next_l2_gas_price` will:

1. **Pass** `validate_resource_bounds` (gateway soft check against `l2_gas_price`)
2. **Pass** `check_fee_bounds` inside `run_validate_entry_point` (blockifier check also uses `l2_gas_price`)
3. **Pass** mempool admission and be queued for sequencing
4. **Fail** `check_fee_bounds` during batcher execution, because the batcher uses `next_l2_gas_price` as the actual block gas price

Conversely, when the price is falling, transactions valid for the next block are incorrectly rejected at the gateway.

The magnitude of the discrepancy is bounded by the EIP-1559 adjustment per block, but under sustained high load the price can rise continuously, widening the gap between the stale gateway reference price and the actual execution price.

### Likelihood Explanation

The condition is triggered whenever the EIP-1559 mechanism adjusts the L2 gas price between blocks, which occurs every block that is not exactly at the gas target. Under normal network load the price fluctuates continuously. No special privileges or unusual conditions are required — any user submitting a transaction with `max_price_per_unit` set to the current block's price (a natural choice) can trigger this path. The TODO comment in the source code confirms the developers are aware the wrong field is being read.

### Recommendation

Replace the `l2_gas_price` read in both `validate_resource_bounds` and `run_validate_entry_point` with `next_l2_gas_price` from the previous block header. This requires:

1. Extending `BlockInfo` (or the `GatewayFixedBlockStateReader` trait) to expose `next_l2_gas_price` from `BlockHeaderWithoutHash`.
2. In `validate_resource_bounds`, compare the transaction's `max_price_per_unit` against `next_l2_gas_price` (not `l2_gas_price`).
3. In `run_validate_entry_point`, populate `block_info.gas_prices.strk_gas_prices.l2_gas_price` with `next_l2_gas_price` before constructing the `BlockContext`, so that `check_fee_bounds` inside the blockifier uses the correct reference price.

### Proof of Concept

1. Observe the current L2 gas price in block N: `P_current`.
2. Compute `P_next = calculate_next_base_gas_price(P_current, gas_used, gas_target, min)` — this is the price for block N+1. When block N is full, `P_next > P_current`.
3. Submit an invoke transaction with `max_price_per_unit = P_current` (satisfying the gateway's threshold check against `P_current`).
4. The gateway's `validate_resource_bounds` computes `threshold = min_gas_price_percentage% * P_current ≤ P_current` → **passes**.
5. The gateway's `run_validate_entry_point` runs `check_fee_bounds` with `block_info.gas_prices.l2_gas_price = P_current` → **passes**.
6. The transaction enters the mempool.
7. The batcher builds block N+1 with gas price `P_next > P_current`. `check_fee_bounds` now checks `max_price_per_unit (= P_current) < P_next` → **fails**, transaction is reverted or dropped.

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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-412)
```rust
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

**File:** crates/apollo_storage/src/header.rs (L85-90)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
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
