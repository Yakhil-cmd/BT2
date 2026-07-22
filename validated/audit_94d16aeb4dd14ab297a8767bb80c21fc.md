### Title
Gateway Admission Validates L2 Gas Price Against Stale `l2_gas_price` Instead of `next_l2_gas_price` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next** block at `next_l2_gas_price` (the EIP-1559-adjusted price already computed and stored in the block header). This is the direct sequencer analog of the Yieldoor bug: using a stale cached field (`l2_gas_price`) instead of the authoritative derived value (`next_l2_gas_price`) for a boundary/threshold decision. The code even carries a TODO acknowledging the error.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the reference price from `gateway_fixed_block_state_reader.get_block_info()`:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `BlockInfo` using `block_header.l2_gas_price.price_in_fri` — the price **for the current (latest committed) block**: [2](#0-1) 

However, `StorageBlockHeader` already stores the authoritative next-block price as a separate field `next_l2_gas_price: GasPrice`, computed via EIP-1559 at block finalization: [3](#0-2) 

The `calculate_next_l2_gas_price_for_fin` function computes this value from `current_l2_gas_price` and `l2_gas_used` at proposal finalization time: [4](#0-3) 

When the batcher executes the transaction, it uses the **next block's** gas prices (the `next_l2_gas_price` from the latest block header), not the current block's `l2_gas_price`. The blockifier's `check_fee_bounds` then compares `resource_bounds.max_price_per_unit` against `block_context.block_info.gas_prices.l2_gas_price`, which is the next block's price: [5](#0-4) 

The gateway's `run_validate_entry_point` also uses the previous block's gas prices (only incrementing the block number, not updating gas prices): [6](#0-5) 

---

### Impact Explanation

The EIP-1559 mechanism continuously adjusts `next_l2_gas_price` relative to `l2_gas_price` based on gas consumption:

**Case 1 — Price rising** (`gas_used > gas_target`, `next_l2_gas_price > l2_gas_price`):  
A transaction with `max_price_per_unit` in the range `[threshold(l2_gas_price), next_l2_gas_price)` passes gateway admission but fails blockifier `check_fee_bounds` during execution. The gateway admits a transaction that will be reverted, wasting mempool capacity and potentially enabling a low-cost DoS.

**Case 2 — Price falling** (`gas_used < gas_target`, `next_l2_gas_price < l2_gas_price`):  
A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, threshold(l2_gas_price))` is rejected by the gateway even though it would succeed in execution. A user submitting a transaction priced correctly for the next block is incorrectly denied admission.

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The EIP-1559 price adjustment is a continuous, normal operation. Any block where `l2_gas_used ≠ gas_target` produces a `next_l2_gas_price` that differs from `l2_gas_price`. With `min_gas_price_percentage = 100` (the default), the threshold equals the full previous-block price, maximizing the gap. No special attacker capability is required — any user submitting a transaction at the "correct" next-block price triggers Case 2.

---

### Recommendation

In `validate_resource_bounds`, replace the read of `l2_gas_price` with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait and `GatewayFixedBlockSyncStateClient` must be updated to expose this field (it is already present in `StorageBlockHeader` and `BlockHeaderWithoutHash`). [7](#0-6) 

---

### Proof of Concept

1. Network is under sustained load: `l2_gas_used > gas_target` for the latest block, so `next_l2_gas_price = P_next > P_curr = l2_gas_price`.
2. User submits an invoke transaction with `max_price_per_unit = P_curr` (exactly the current block's price, which is below `P_next`).
3. **Gateway `validate_resource_bounds`**: threshold = `100% × P_curr = P_curr`; `max_price_per_unit = P_curr ≥ P_curr` → **PASSES**.
4. Transaction enters the mempool.
5. Batcher builds the next block using `P_next` as the block's L2 gas price.
6. **Blockifier `check_fee_bounds`**: `max_price_per_unit = P_curr < P_next` → `MaxGasPriceTooLow` error → transaction **FAILS** execution.

For the rejection case (price falling):
1. `next_l2_gas_price = P_next < P_curr`.
2. User submits with `max_price_per_unit = P_next` (correct for execution).
3. **Gateway**: threshold = `P_curr`; `P_next < P_curr` → **REJECTED** with `GAS_PRICE_TOO_LOW`.
4. Transaction would have succeeded in the next block but is denied admission.

The TODO comment at line 229 of `stateful_transaction_validator.rs` is the code's own acknowledgment of this root cause: `// TODO(Arni): getnext_l2_gas_price from the block header.` [8](#0-7)

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

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L55-77)
```rust
pub fn calculate_next_l2_gas_price_for_fin(
    current_l2_gas_price: GasPrice,
    height: BlockNumber,
    l2_gas_used: GasAmount,
    override_l2_gas_price_fri: Option<u128>,
    min_l2_gas_price_per_height: &[PricePerHeight],
    fee_actual: Option<GasPrice>,
) -> GasPrice {
    if let Some(override_value) = override_l2_gas_price_fri {
        info!(
            "L2 gas price ({}) is not updated, remains on override value of {override_value} fri",
            current_l2_gas_price.0
        );
        return GasPrice(override_value);
    }
    let gas_target = VersionedConstants::latest_constants().gas_target;
    let config_min = get_min_gas_price_for_height(height, min_l2_gas_price_per_height);
    let effective_min = match fee_actual {
        Some(fa) => GasPrice(max(config_min.0, fa.0)),
        None => config_min,
    };
    calculate_next_base_gas_price(current_l2_gas_price, l2_gas_used, gas_target, effective_min)
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L418-424)
```rust
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
```
