### Title
Gateway Admission Validates L2 Gas Price Against Stale `l2_gas_price` Instead of `next_l2_gas_price` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check compares a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next** block, whose price is `next_l2_gas_price`. The two values diverge every time the EIP-1559 fee market adjusts. The code even carries an open TODO acknowledging the wrong field is used. The result is systematic wrong admission decisions: transactions priced between the two values are either incorrectly rejected (price is falling) or incorrectly admitted and then reverted at execution (price is rising).

---

### Finding Description

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

- `l2_gas_price` — the price **charged in the block that was just committed**
- `next_l2_gas_price` — the EIP-1559-derived price **for the block about to be built** [1](#0-0) 

When `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` from the latest committed block, it maps `block_header.l2_gas_price.price_in_fri` into `strk_gas_prices.l2_gas_price` and **silently drops** `block_header.next_l2_gas_price`: [2](#0-1) 

`validate_resource_bounds` then reads that stale field and uses it as the admission threshold: [3](#0-2) 

The developer who wrote this code left an explicit TODO acknowledging the wrong value is being used:

```
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [4](#0-3) 

The threshold is then applied in `validate_tx_l2_gas_price_within_threshold`: [5](#0-4) 

The `BlockInfo` struct passed to the blockifier for the actual `validate` entry-point call also uses the same stale `block_info` (with only `block_number` bumped), so the gas price seen by the Cairo validator contract is equally stale: [6](#0-5) 

---

### Impact Explanation

The EIP-1559 L2 fee market adjusts `next_l2_gas_price` every block based on gas consumed vs. the target. During any period of sustained high or low utilisation the two values diverge:

| Scenario | `l2_gas_price` (prev block) | `next_l2_gas_price` (next block) | Effect |
|---|---|---|---|
| Gas price rising | P | P + δ | Tx with `max_price ∈ [P, P+δ)` passes gateway, fails at execution with `InsufficientResourceBounds` → **invalid tx admitted** |
| Gas price falling | P | P − δ | Tx with `max_price ∈ [P−δ, P)` is rejected by gateway even though it would succeed at execution → **valid tx rejected** |

The "invalid tx admitted" branch is the more dangerous one: the transaction enters the mempool, consumes batcher resources, and is ultimately reverted, wasting sequencer capacity and potentially causing the user to pay fees for a failed transaction. The "valid tx rejected" branch is a liveness/UX failure that denies service to legitimate users.

This matches the impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The L2 fee market runs continuously. Any block whose gas consumption differs from the target causes `next_l2_gas_price ≠ l2_gas_price`. On a live network this is the common case, not the exception. No special privileges are required; any user submitting a V3 (`AllResources`) transaction with a `max_price_per_unit` that falls in the gap between the two prices will trigger the bug. The gap grows cumulatively during sustained high or low load, widening the affected price range over time — exactly the "errors are cumulative" property highlighted in the external report.

---

### Recommendation

1. Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (add it to the returned `BlockInfo` or as a separate method).
2. In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, read `block_header.next_l2_gas_price` and store it.
3. In `validate_resource_bounds`, replace the read of `gas_prices.strk_gas_prices.l2_gas_price` with the `next_l2_gas_price` value — this is exactly what the existing TODO comment requests.
4. Ensure the same `next_l2_gas_price` is also used as the gas price in the `BlockContext` passed to the blockifier `validate` entry-point call, so the two checks are consistent.

---

### Proof of Concept

1. Observe the current committed block has `l2_gas_price = P` and `next_l2_gas_price = P + δ` (any block with above-target gas usage).
2. Submit a V3 `InvokeTransaction` with `resource_bounds.l2_gas.max_price_per_unit = P` (equal to the stale threshold, so `validate_resource_bounds` passes with `min_gas_price_percentage = 100`).
3. The gateway admits the transaction into the mempool.
4. The batcher picks the transaction for the next block, which runs at price `P + δ`.
5. `check_fee_bounds` inside `perform_pre_validation_stage` computes the minimum required fee using the actual block gas price `P + δ`, finds `max_price_per_unit = P < P + δ`, and the transaction is reverted with `InsufficientResourceBounds`.

The gateway's admission decision was wrong: it used `P` (stale) instead of `P + δ` (correct next-block price) as the threshold. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** crates/starknet_api/src/block.rs (L231-248)
```rust
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct BlockHeaderWithoutHash {
    pub parent_hash: BlockHash,
    pub block_number: BlockNumber,
    pub l1_gas_price: GasPricePerToken,
    pub l1_data_gas_price: GasPricePerToken,
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
    pub state_root: GlobalRoot,
    pub sequencer: SequencerContractAddress,
    pub timestamp: BlockTimestamp,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub starknet_version: StarknetVersion,
    // TODO(AndrewL): Add this field into the block hash.
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
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
