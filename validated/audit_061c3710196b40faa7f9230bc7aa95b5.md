### Title
Gateway Stateful Admission Uses Stale Previous-Block L2 Gas Price Instead of Next-Block Price, Causing Incorrect Admission/Rejection Decisions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful `validate_resource_bounds` check compares a transaction's `max_price_per_unit` against the **previous committed block's** L2 gas price. The actual execution block uses a **different** L2 gas price computed by the EIP-1559 fee market. This mismatch causes the gateway to admit transactions that will fail at execution (wasting sequencer resources) and to reject transactions that would have been valid for the actual execution block.

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the threshold is derived from the previous block's STRK L2 gas price:

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

The threshold is then computed as `min_gas_price_percentage% × previous_block_l2_gas_price` (default: 100%):

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
``` [2](#0-1) 

The same stale block info is also used to build the `BlockContext` for the blockifier's `perform_pre_validation_stage` at the gateway (only the block number is incremented, not the gas prices):

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

The actual execution block's L2 gas price is computed by the consensus orchestrator via `calculate_next_base_gas_price` (EIP-1559), which adjusts the price based on gas usage in the **current** block:

```rust
let price_change = (price_u256 * gas_delta) / denominator;
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [4](#0-3) 

With `gas_price_max_change_denominator = 48` (from versioned constants), the next block's price can differ from the previous block's price by up to ~2% per block. [5](#0-4) 

The `GatewayFixedBlockSyncStateClient` caches the block info via `OnceCell`, so the stale price is locked in for the entire lifetime of the validator instance:

```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}
``` [6](#0-5) 

The TODO comment in the production code explicitly acknowledges the wrong price is being used: [7](#0-6) 

Additionally, `validate_tx_l2_gas_price_within_threshold` entirely skips the check for `ValidResourceBounds::L1Gas` transactions:

```rust
ValidResourceBounds::L1Gas(_) => {
    // No validation required for legacy transactions.
}
``` [8](#0-7) 

### Impact Explanation

Two concrete failure modes arise from the price mismatch:

**Mode 1 — Gateway admits transactions that fail at execution (gas price rising):**
When the previous block was heavily loaded, the EIP-1559 formula raises the next block's L2 gas price by up to ~2%. A transaction with `max_price_per_unit` exactly at the previous block's price passes the gateway threshold (100% × previous price) but fails `check_fee_bounds` in `AccountTransaction::perform_pre_validation_stage` during actual execution, because the actual block's price is higher. These transactions are admitted to the mempool, consume sequencer validation resources, and are then discarded — a resource-exhaustion vector.

**Mode 2 — Gateway rejects valid transactions (gas price falling):**
When the previous block was lightly loaded, the next block's price decreases. A transaction with `max_price_per_unit` slightly below the previous block's price is rejected at the gateway even though it would satisfy the actual execution block's lower price. This is a false-negative admission decision.

Both modes match the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The attack is unprivileged and requires no special access. Any user can observe on-chain gas usage in the current block and predict the next block's EIP-1559 price deterministically. By filling the current block with transactions (driving gas usage above `gas_target`), an attacker can guarantee the next block's price will be higher than the previous block's price, then submit transactions priced between the two values. These transactions pass gateway admission but fail at execution. The default `min_gas_price_percentage = 100` provides no buffer against this ~2% price increase. [9](#0-8) 

### Recommendation

Replace `previous_block_l2_gas_price` with the **computed next-block L2 gas price** in `validate_resource_bounds`. The consensus orchestrator already exposes `calculate_next_l2_gas_price_for_fin` / `calculate_next_base_gas_price` for this purpose. The gateway should call the same EIP-1559 formula using the current block's gas usage to derive the price that will actually be used for execution, then compare the transaction's `max_price_per_unit` against that value. Alternatively, set `min_gas_price_percentage` to a value that accounts for the maximum per-block price increase (e.g., `100 + ceil(100/gas_price_max_change_denominator)` ≈ 103 with the current denominator of 48) so that admitted transactions are guaranteed to cover the next block's price even in the worst case.

### Proof of Concept

1. Observe that the current block's gas usage is `gas_used > gas_target` (e.g., by monitoring the mempool).
2. Compute `next_price = calculate_next_base_gas_price(current_price, gas_used, gas_target, min_price)` — this is deterministic and public.
3. Submit an `InvokeTransaction` V3 with `AllResourceBounds` where `l2_gas.max_price_per_unit = current_price` (satisfies the gateway threshold of 100% × `current_price`) but `current_price < next_price`.
4. The gateway's `validate_resource_bounds` passes: `current_price >= 100% × current_price`. ✓
5. The gateway's `run_validate_entry_point` also passes because it uses the same stale `block_info` with `current_price` as the block's gas price. ✓
6. The transaction is admitted to the mempool.
7. At execution time, the batcher builds the block with `next_price > current_price`. `check_fee_bounds` in `AccountTransaction::perform_pre_validation_stage` compares `l2_gas.max_price_per_unit (= current_price) < actual_gas_price (= next_price)` and returns `ResourceBoundsError::MaxGasPriceTooLow`. The transaction fails.
8. Repeat to continuously fill the mempool with transactions that pass admission but fail execution.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L227-243)
```rust
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L385-387)
```rust
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L126-129)
```rust
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_3.json (L1-9)
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-23)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
