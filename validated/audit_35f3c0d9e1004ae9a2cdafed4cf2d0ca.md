### Title
Gateway Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Systematic Mempool Admission/Rejection Errors - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price` (the price that was used for the block that was just committed). However, the transaction will actually be executed in the **next** block, whose L2 gas price is already deterministically computed and stored in the block header as `next_l2_gas_price`. The gateway reads the wrong field, creating a systematic mismatch: under high load (rising price), transactions that pass gateway admission will be rejected by the blockifier at execution time; under low load (falling price), transactions that would succeed at execution are rejected at the gateway.

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price reference from the latest committed block's `gas_prices.strk_gas_prices.l2_gas_price`:

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

The TODO comment itself acknowledges the bug. The correct value to use is `next_l2_gas_price`, which is deterministically computed by `calculate_next_l2_gas_price_for_fin` at block finalization and stored in `BlockHeaderWithoutHash.next_l2_gas_price` / `StorageBlockHeader.next_l2_gas_price`.

The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` from the block header but only copies `block_header.l2_gas_price` — it never reads `block_header.next_l2_gas_price`, so the correct value is structurally inaccessible through the current `GatewayFixedBlockStateReader` interface.

The EIP-1559 price update formula is:

```
price_change = price * gas_delta / (gas_target * gas_price_max_change_denominator)
```

With `gas_price_max_change_denominator = 48` and `gas_target = 1,040,000,000`, `max_block_size = 5,800,000,000` (v0.14.3/v0.14.4), a completely full block produces:

```
gas_delta = 5,800,000,000 − 1,040,000,000 = 4,760,000,000
price_change ≈ price × 9.54%
```

So `next_l2_gas_price` can be up to ~9.54% above `l2_gas_price` in a single block. The gateway's threshold check (`min_gas_price_percentage = 100` by default) admits any transaction with `max_price_per_unit ≥ l2_gas_price`, but the blockifier's `check_fee_bounds` at execution time enforces `max_price_per_unit ≥ next_l2_gas_price`. Transactions in the gap `[l2_gas_price, next_l2_gas_price)` pass the gateway and fail the blockifier.

### Impact Explanation

**Admission of invalid transactions (rising price / high load):** A transaction with `max_price_per_unit = l2_gas_price` passes `validate_resource_bounds`, enters the mempool, and is handed to the batcher. The batcher builds block N+1 with `l2_gas_price = next_l2_gas_price`. The blockifier's `AccountTransaction::perform_pre_validation_stage → check_fee_bounds` returns `TransactionFeeError::InsufficientResourceBounds { MaxGasPriceTooLow }`. The transaction is dropped without being included in the block. The user's transaction is silently lost; they must resubmit.

**Rejection of valid transactions (falling price / low load):** When `next_l2_gas_price < l2_gas_price`, a transaction with `max_price_per_unit` in `[next_l2_gas_price, l2_gas_price)` would succeed at execution but is rejected at the gateway with `GAS_PRICE_TOO_LOW`.

Both directions match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

The L2 gas price changes every block whenever gas usage deviates from the target. Under normal network load (blocks consistently above or below target), the price drifts continuously. The ~9.54% maximum per-block change means the gap between `l2_gas_price` and `next_l2_gas_price` is routinely non-zero. Any user who sets `max_price_per_unit` to exactly the current block's price (the natural "just enough" value) is affected. No special attacker capability is required — ordinary transaction submission triggers the bug.

### Recommendation

1. Extend `GatewayFixedBlockStateReader` to expose `next_l2_gas_price` from the block header.
2. In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, read `block_header.next_l2_gas_price` and return it alongside or instead of `l2_gas_price`.
3. In `validate_resource_bounds`, replace `previous_block_l2_gas_price` with the `next_l2_gas_price` value from the block header as the threshold reference.

### Proof of Concept

**Setup:** Network at v0.14.4. Block N is completely full (`gas_used = 5,800,000,000`). Block N's `l2_gas_price = 8,000,000,000 fri` (8 Gwei). Computed `next_l2_gas_price ≈ 8,763,200,000 fri` (~9.54% increase).

**Step 1 — User submits transaction:**
```
max_price_per_unit = 8,000,000,000  // exactly the current block price
```

**Step 2 — Gateway `validate_resource_bounds`:**
```
previous_block_l2_gas_price = 8,000,000,000  // reads l2_gas_price, NOT next_l2_gas_price
threshold = 100% × 8,000,000,000 = 8,000,000,000
8,000,000,000 >= 8,000,000,000  → PASS
```
Transaction is admitted to the mempool.

**Step 3 — Batcher builds block N+1:**
```
block_context.gas_prices.strk_gas_prices.l2_gas_price = 8,763,200,000
```

**Step 4 — Blockifier `check_fee_bounds`:**
```
max_price_per_unit = 8,000,000,000 < 8,763,200,000 = actual_gas_price
→ ResourceBoundsError::MaxGasPriceTooLow
→ TransactionFeeError::InsufficientResourceBounds
→ TransactionPreValidationError
```
Transaction is dropped. User's transaction is silently lost.

---

**Relevant code locations:**

`validate_resource_bounds` reads the wrong price field: [1](#0-0) 

The TODO acknowledges the correct field should be `next_l2_gas_price`: [2](#0-1) 

`GatewayFixedBlockSyncStateClient` never reads `next_l2_gas_price` from the block header: [3](#0-2) 

`next_l2_gas_price` is stored in the block header but not exposed: [4](#0-3) 

EIP-1559 price update formula with `gas_price_max_change_denominator = 48`: [5](#0-4) 

Versioned constants confirming `gas_price_max_change_denominator = 48`: [6](#0-5) 

Blockifier `check_fee_bounds` that enforces the actual next-block price at execution: [7](#0-6)

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L117-139)
```rust
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

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_4.json (L1-9)
```json
{
    "fee_proposal_margin_ppt": 2,
    "fee_proposal_window_size": 10,
    "gas_price_max_change_denominator": 48,
    "gas_target": 1040000000,
    "max_block_size": 5800000000,
    "min_gas_price": "0x1dcd65000",
    "l1_gas_price_margin_percent": 10
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-458)
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
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```
