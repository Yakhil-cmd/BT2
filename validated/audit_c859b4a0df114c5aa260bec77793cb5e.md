After thorough investigation of the codebase, I found a valid analog to the external bug report.

---

### Title
Gateway Stateful Validator Uses Stale Previous-Block L2 Gas Price as Admission Threshold, Causing False Rejections and False Acceptances — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `validate_resource_bounds` function in `StatefulTransactionValidator` computes the L2 gas price admission threshold using the **previous block's** L2 gas price, while the actual next block's L2 gas price is computed by the EIP-1559 formula and can differ materially. This causes the gateway to incorrectly reject valid transactions (when the next block price is lower) and to accept transactions that will fail during batcher execution (when the next block price is higher). The code itself acknowledges the defect with a TODO comment.

### Finding Description

In `validate_resource_bounds` (lines 223–243), the gateway fetches the previous block's L2 gas price via `gateway_fixed_block_state_reader.get_block_info()` and passes it directly to the threshold check:

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

The threshold is then computed as:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold { ... }
``` [2](#0-1) 

The actual next block's L2 gas price is computed by `calculate_next_base_gas_price` using the EIP-1559 formula, which adjusts the price up or down based on block utilization:

```rust
let price_change = (price_u256 * gas_delta) / denominator;
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [3](#0-2) 

Critically, `run_validate_entry_point` also builds its block context from the same stale `get_block_info()` call, only incrementing the block number:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [4](#0-3) 

This means both the soft threshold check (`validate_resource_bounds`) and the hard blockifier check (`check_fee_bounds` inside `perform_pre_validation_stage`) use block N's gas prices, while the batcher executes transactions against block N+1's actual gas prices. The `GatewayFixedBlockSyncStateClient` caches the block info in a `OnceCell`, so it never refreshes within a single validator lifetime:

```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}
``` [5](#0-4) 

The `SyncStateReaderFactory` snapshots the latest block number at the moment of transaction arrival and never updates it:

```rust
let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;
...
let gateway_fixed_block_sync_state_client = GatewayFixedBlockSyncStateClient::new(
    self.shared_state_sync_client.clone(),
    latest_block_number,
);
``` [6](#0-5) 

### Impact Explanation

**False acceptance (invalid transactions admitted):** When the next block's L2 gas price is higher than the previous block's (high utilization), a transaction with `max_l2_gas_price` between the stale threshold and the actual next block price passes both the gateway soft check and the blockifier hard check (both use block N prices), enters the mempool, and then fails during batcher execution when the actual block N+1 price is enforced. This matches: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

**False rejection (valid transactions rejected):** When the next block's L2 gas price is lower than the previous block's (low utilization), a transaction with `max_l2_gas_price` above the actual next block price but below the stale threshold is incorrectly rejected at the gateway. This matches: *"Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 formula adjusts the L2 gas price every block based on utilization relative to the gas target. Under normal network conditions the price moves continuously, so the next block's price routinely differs from the previous block's price. The window of affected transactions (between the stale threshold and the actual next block price) is non-trivial and grows with block utilization variance. The TODO comment in the production code confirms the developers are aware the wrong price is being used.

### Recommendation

Replace the stale `previous_block_l2_gas_price` with the next block's L2 gas price, computed by `calculate_next_base_gas_price` using the current block's utilization data, as the TODO comment already prescribes:

```rust
// Replace:
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;

// With:
let next_block_l2_gas_price = calculate_next_base_gas_price(
    previous_block_l2_gas_price,
    previous_block_gas_used,
    gas_target,
    min_gas_price,
);
```

Alternatively, read `next_l2_gas_price` directly from the block header once it is stored there (as the TODO suggests).

### Proof of Concept

**False acceptance scenario (`min_gas_price_percentage = 100`):**

| Step | Value |
|------|-------|
| Previous block L2 gas price (block N) | 100 fri |
| Next block L2 gas price (block N+1, EIP-1559, high utilization) | 112 fri |
| Threshold (100% × 100) | 100 fri |
| Transaction `max_l2_gas_price` | 105 fri |
| Gateway soft check: 105 ≥ 100 | **PASS** (incorrect) |
| Blockifier hard check (uses block N prices): 105 ≥ 100 | **PASS** (incorrect) |
| Batcher execution (uses block N+1 prices): 105 < 112 | **FAIL** |

**False rejection scenario (`min_gas_price_percentage = 100`):**

| Step | Value |
|------|-------|
| Previous block L2 gas price (block N) | 100 fri |
| Next block L2 gas price (block N+1, EIP-1559, low utilization) | 88 fri |
| Threshold (100% × 100) | 100 fri |
| Transaction `max_l2_gas_price` | 93 fri |
| Gateway soft check: 93 < 100 | **REJECT** (incorrect — transaction would succeed at 88 fri) |

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-383)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L124-129)
```rust
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-27)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}

impl GatewayFixedBlockSyncStateClient {
    pub fn new(state_sync_client: SharedStateSyncClient, block_number: BlockNumber) -> Self {
        Self { state_sync_client, block_number, block_info_cache: OnceCell::new() }
```

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L531-549)
```rust
        let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;

        // If no blocks exist yet, return genesis state readers for bootstrap transactions.
        let Some(latest_block_number) = latest_block_number else {
            info!("No blocks found yet; using genesis state readers for bootstrap transactions.");
            return Ok((GenesisStateReader.into(), GenesisFixedBlockStateReader.into()));
        };

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
