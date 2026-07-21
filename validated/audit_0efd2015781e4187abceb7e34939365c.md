### Title
Gateway Stateful Validator Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` for Resource-Bound Admission — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` compares a transaction's `max_price_per_unit` against the **current block's** `strk_gas_prices.l2_gas_price`, but the transaction will be executed in the **next block** whose gas price is `next_l2_gas_price` (a distinct field in `BlockHeaderWithoutHash`). An in-code `TODO` explicitly acknowledges the wrong field is being read. When the L2 gas price is rising, transactions whose `max_price_per_unit` falls between the two prices pass gateway admission but fail blockifier pre-validation at execution time. When the price is falling, valid transactions are incorrectly rejected at the gateway.

### Finding Description

`BlockHeaderWithoutHash` carries two separate L2 gas price fields:

- `l2_gas_price: GasPricePerToken` — the price that was **used in the current (previous) block**
- `next_l2_gas_price: GasPrice` — the EIP-1559-style price that **will be used in the next block** [1](#0-0) 

The consensus orchestrator computes `next_l2_gas_price` via `calculate_next_l2_gas_price` and stores it in the block header; the batcher uses this value as the gas price for the block it is building. [2](#0-1) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` maps the block header into a `BlockInfo` struct, but only copies `l2_gas_price.price_in_fri` — `next_l2_gas_price` is silently dropped and never exposed through the `GatewayFixedBlockStateReader` interface. [3](#0-2) 

`StatefulTransactionValidator::validate_resource_bounds` then reads `strk_gas_prices.l2_gas_price` from the returned `BlockInfo` and uses it as the threshold. The `TODO` comment in the source code explicitly acknowledges the wrong field is being used:

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
``` [4](#0-3) 

`validate_tx_l2_gas_price_within_threshold` then computes `threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price` and rejects the transaction if `tx_l2_gas_price < threshold`. [5](#0-4) 

The same stale price is also propagated into the `BlockContext` used for the blockifier `__validate__` call inside `run_validate_entry_point` (only `block_number` is incremented; gas prices are not updated to `next_l2_gas_price`): [6](#0-5) 

### Impact Explanation

**Scenario A — gas price rising (`next_l2_gas_price > l2_gas_price`):**

The gateway threshold is computed from the lower, stale price. Any transaction whose `max_price_per_unit` satisfies:

```
l2_gas_price * (pct/100)  ≤  tx_price  <  next_l2_gas_price * (pct/100)
```

passes gateway admission and enters the mempool, but will fail `check_fee_bounds` in the blockifier during actual execution in the batcher (which uses the correct `next_l2_gas_price`). The gateway has admitted an invalid transaction.

**Scenario B — gas price falling (`next_l2_gas_price < l2_gas_price`):**

The gateway threshold is computed from the higher, stale price. Transactions whose `max_price_per_unit` satisfies:

```
next_l2_gas_price * (pct/100)  ≤  tx_price  <  l2_gas_price * (pct/100)
```

are rejected at the gateway even though they would succeed in the next block. Valid transactions are incorrectly denied admission.

Both scenarios match the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The L2 gas price changes every block via the EIP-1559-style fee market. Under any non-trivial load the two prices diverge. The discrepancy is proportional to the gas-usage delta between consecutive blocks. No privilege is required; any user submitting a V3 `AllResources` transaction during a period of changing gas prices triggers the condition. The `min_gas_price_percentage` default of `100` (i.e., full threshold enforcement) maximises the window of incorrect decisions. [7](#0-6) 

### Recommendation

1. Extend `GatewayFixedBlockStateReader` to expose `next_l2_gas_price` alongside `BlockInfo`.
2. In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, read `block_header.next_l2_gas_price` and return it through the extended interface.
3. Replace the stale `strk_gas_prices.l2_gas_price` read in `validate_resource_bounds` with the `next_l2_gas_price` value.
4. Apply the same correction to the `BlockContext` constructed in `run_validate_entry_point` so that the blockifier `__validate__` call also uses the correct next-block gas price.

### Proof of Concept

1. Observe the current L2 gas price from the latest block header: `P_current`.
2. Observe `next_l2_gas_price` from the same header: `P_next > P_current` (network under load).
3. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P_current` (satisfies the stale threshold, below the correct threshold).
4. The gateway's `validate_resource_bounds` computes `threshold = P_current * (100/100) = P_current` and accepts the transaction (`P_current >= P_current`).
5. The transaction enters the mempool.
6. When the batcher attempts to include the transaction in the next block (whose gas price is `P_next`), `check_fee_bounds` computes `actual_gas_price = P_next > P_current = max_price_per_unit` and raises `ResourceBoundsError::MaxGasPriceTooLow`, causing the transaction to fail pre-validation and be dropped — confirming the gateway admitted an invalid transaction. [8](#0-7)

### Citations

**File:** crates/starknet_api/src/block.rs (L232-248)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L425-441)
```rust
    /// Returns the next L2 gas price without mutating context. Used when building the fin and when
    /// updating at decision time.
    fn calculate_next_l2_gas_price(&self, height: BlockNumber, l2_gas_used: GasAmount) -> GasPrice {
        let fee_actual = compute_fee_actual(
            &self.fee_proposals_window,
            height,
            VersionedConstants::latest_constants().fee_proposal_window_size,
        );
        calculate_next_l2_gas_price_for_fin(
            self.l2_gas_price,
            height,
            l2_gas_used,
            self.config.dynamic_config.override_l2_gas_price_fri,
            &self.config.dynamic_config.min_l2_gas_price_per_height,
            fee_actual,
        )
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
