### Title
Gateway L2 Gas Price Threshold Validation Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` from Block Header - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check validates a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will actually execute in the **next** block at `next_l2_gas_price` — a distinct, EIP-1559-adjusted value stored in the same block header. The code even carries a developer TODO acknowledging the wrong field is being read. When the two prices diverge (which is the normal case under any non-zero load), the gateway either admits transactions that will be rejected by the batcher, or rejects transactions that would succeed.

### Finding Description

`BlockHeaderWithoutHash` carries two separate L2 gas price fields:

- `l2_gas_price: GasPricePerToken` — the price at which transactions in the **current** block were charged.
- `next_l2_gas_price: GasPrice` — the EIP-1559-adjusted price that will be used for the **next** block. [1](#0-0) 

When the consensus context finalises a block it writes `self.l2_gas_price` (the dynamically computed next price) into `next_l2_gas_price` and the current execution price into `l2_gas_price`: [2](#0-1) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` reads only `block_header.l2_gas_price` into the returned `BlockInfo`; it never reads `block_header.next_l2_gas_price`: [3](#0-2) 

`StatefulTransactionValidator::validate_resource_bounds` then uses that stale price as the reference for the threshold check, with a TODO comment acknowledging the correct field should be `next_l2_gas_price`: [4](#0-3) 

The same stale `BlockInfo` is also used to build the `BlockContext` passed to the blockifier's `perform_pre_validation_stage` inside `run_validate_entry_point`, so `check_fee_bounds` also compares against the wrong price: [5](#0-4) 

The batcher, by contrast, receives the true `next_l2_gas_price` via `ProposalInit.l2_gas_price_fri` and uses it as the block context gas price when executing transactions. So the price the gateway validates against and the price the batcher executes against are structurally different values.

### Impact Explanation

**Case 1 — price rising (block above gas target):** `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit` satisfying `threshold × l2_gas_price ≤ max_price < next_l2_gas_price` passes gateway admission but will be rejected by the batcher's `check_fee_bounds` with `MaxGasPriceTooLow`. The gateway has admitted an invalid transaction.

**Case 2 — price falling (block below gas target):** `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit` satisfying `threshold × next_l2_gas_price ≤ max_price < threshold × l2_gas_price` would succeed in the batcher but is rejected by the gateway. Valid transactions are incorrectly refused.

Both directions are reachable under normal network conditions because the EIP-1559 mechanism continuously adjusts `next_l2_gas_price` based on block utilisation. [6](#0-5) 

### Likelihood Explanation

The bug is triggered on every block where gas utilisation differs from the gas target — i.e., virtually every block in production. Any user whose `max_price_per_unit` falls in the gap between `l2_gas_price` and `next_l2_gas_price` is affected without any special action. No privileged access is required; a standard `InvokeTransaction` or `DeclareTransaction` with `AllResources` bounds is sufficient.

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace the `l2_gas_price` field in the returned `BlockInfo` with `block_header.next_l2_gas_price` (converted to `NonzeroGasPrice`). This is exactly what the TODO comment at line 229 of `stateful_transaction_validator.rs` requests. The same fix must be applied to the `BlockInfo` constructed for `run_validate_entry_point` so that the blockifier pre-validation also uses the correct price.

### Proof of Concept

1. Observe block N with `l2_gas_price = 100 fri` and `next_l2_gas_price = 115 fri` (block was above gas target).
2. Submit an `InvokeTransaction` with `AllResources` bounds: `l2_gas.max_price_per_unit = 110 fri`.
3. Gateway calls `validate_resource_bounds`: threshold = `min_gas_price_percentage% × 100 = 90 fri` (assuming 90%). `110 ≥ 90` → **passes**.
4. Gateway calls `run_validate_entry_point` with a `BlockContext` whose `l2_gas_price = 100 fri`. `check_fee_bounds` checks `110 ≥ 100` → **passes**.
5. Transaction is admitted to the mempool.
6. Batcher builds block N+1 with `l2_gas_price = 115 fri`. `check_fee_bounds` checks `110 ≥ 115` → **fails** with `MaxGasPriceTooLow`. Transaction is rejected at execution time despite having passed all gateway checks. [7](#0-6) [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L316-330)
```rust
        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L54-77)
```rust
/// Compute the next L2 gas price (for the fin or for updating state). Respects override when set.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
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
```
