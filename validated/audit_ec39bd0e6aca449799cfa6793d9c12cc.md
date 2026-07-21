### Title
Gateway Stateful Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` as Threshold — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds()` compares a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next** block whose L2 gas price is the pre-computed `next_l2_gas_price` stored in the block header. The code even carries a `TODO` acknowledging this. The mismatch causes the gateway to admit transactions that will fail at execution (when the next block price is higher) and to reject transactions that would succeed (when the next block price is lower).

---

### Finding Description

The block header stores two distinct L2 gas price fields:

- `l2_gas_price` — the price **used in the current (previous) block**
- `next_l2_gas_price` — the EIP-1559-computed price **for the next block**, already committed to the header [1](#0-0) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client()` constructs a `BlockInfo` from the block header but maps only `block_header.l2_gas_price` into `block_info.gas_prices`. The `next_l2_gas_price` field is silently dropped and never exposed through `BlockInfo`. [2](#0-1) 

`validate_resource_bounds()` then reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` as the threshold. The `TODO` comment on line 229 explicitly acknowledges the bug:

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
``` [3](#0-2) 

The threshold is then computed as `previous_block_l2_gas_price * min_gas_price_percentage / 100`: [4](#0-3) 

The same stale `block_info` is also passed into `run_validate_entry_point()` for the blockifier pre-validation, so the blockifier's `check_fee_bounds` inside the gateway also uses the wrong price: [5](#0-4) 

However, when the batcher actually executes the transaction, it builds the block context with the real next-block prices (derived from `next_l2_gas_price`), so the two validation environments diverge.

---

### Impact Explanation

**Case 1 — Congested previous block (`next_l2_gas_price > l2_gas_price`):**

The EIP-1559 formula raises the price when gas usage exceeds the target. The gateway threshold is computed from the stale lower price. Transactions with `max_price_per_unit` in the range `[l2_gas_price × pct/100, next_l2_gas_price × pct/100)` pass both the admission check and the gateway blockifier validation, are admitted to the mempool, but will fail at execution time in the batcher with `MaxGasPriceTooLow`. Invalid transactions are accepted.

**Case 2 — Light previous block (`next_l2_gas_price < l2_gas_price`):**

The threshold is computed from the stale higher price. Transactions with `max_price_per_unit` in the range `[next_l2_gas_price × pct/100, l2_gas_price × pct/100)` are rejected at the gateway even though they would succeed at execution. Valid transactions are incorrectly rejected.

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The EIP-1559 price adjustment per block is bounded by `gas_price_max_change_denominator`, so the divergence between `l2_gas_price` and `next_l2_gas_price` is bounded per block. However, under sustained high or low load the two values can diverge significantly. The `min_gas_price_percentage` default is 100%, meaning the full stale price is used as the threshold, maximising the window of incorrect admission/rejection. The bug is triggered on every transaction validation when the previous block's gas usage differs from the target — a routine condition.

---

### Recommendation

`GatewayFixedBlockStateReader` should expose `next_l2_gas_price` from the block header. `validate_resource_bounds()` should use `next_l2_gas_price` as the threshold instead of `l2_gas_price`. Similarly, `run_validate_entry_point()` should substitute `next_l2_gas_price` for `l2_gas_price` when constructing the `BlockInfo` used for blockifier pre-validation, so that both the admission check and the blockifier validation agree with the price the batcher will actually use.

---

### Proof of Concept

1. Observe that `BlockHeaderWithoutHash` carries both `l2_gas_price` and `next_l2_gas_price`. [6](#0-5) 

2. `GatewayFixedBlockSyncStateClient` maps only `l2_gas_price` into `BlockInfo`; `next_l2_gas_price` is dropped. [7](#0-6) 

3. `validate_resource_bounds()` reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` (the dropped stale value) as the threshold. [8](#0-7) 

4. The batcher builds block context with the actual next-block prices (from `next_l2_gas_price`), creating a divergence. [9](#0-8) 

5. Construct a scenario: previous block used 90% of `max_block_size` (gas_target = 50%). EIP-1559 raises `next_l2_gas_price` by ~`price / gas_price_max_change_denominator`. Submit a transaction with `max_price_per_unit = l2_gas_price`. The gateway admits it (threshold = `l2_gas_price`). The batcher rejects it at execution (`MaxGasPriceTooLow`) because the block context uses `next_l2_gas_price > l2_gas_price`.

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

**File:** crates/apollo_batcher/src/batcher.rs (L699-717)
```rust
        Ok(BlockInfo {
            block_number: header.block_number,
            block_timestamp: header.timestamp,
            sequencer_address: header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_wei)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_wei)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_wei)?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_fri)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_fri)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_fri)?,
                },
            },
            use_kzg_da: header.l1_da_mode.is_use_kzg_da(),
            starknet_version: header.starknet_version,
        })
```
