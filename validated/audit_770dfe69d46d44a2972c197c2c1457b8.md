### Title
Gateway L2 Gas Price Threshold Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` from Block Header — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` validates incoming transactions' L2 gas price against `block_info.gas_prices.strk_gas_prices.l2_gas_price`, which is the L2 gas price **of the previous committed block**. The correct reference value is `block_header.next_l2_gas_price` — the EIP-1559-derived price that will apply to the **next block being built**. The `GatewayFixedBlockSyncStateClient` never maps `next_l2_gas_price` into `BlockInfo`, so the stale value is silently used. The code itself acknowledges this with an explicit TODO: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Finding Description

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

- `l2_gas_price` — the price that was used for transactions **inside** the committed block.
- `next_l2_gas_price` — the EIP-1559-adjusted price that **must** be used for transactions in the **next** block. [1](#0-0) 

When a new block is committed, the sequencer stores `next_l2_gas_price: self.l2_gas_price` in the block header, where `self.l2_gas_price` is the freshly computed EIP-1559 price for the upcoming block: [2](#0-1) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` reads the latest committed block header and constructs a `BlockInfo`, but maps only `block_header.l2_gas_price` into `gas_prices.strk_gas_prices.l2_gas_price` — `block_header.next_l2_gas_price` is completely ignored: [3](#0-2) 

`validate_resource_bounds` then reads this stale value and uses it as the threshold reference: [4](#0-3) 

The same stale `block_info` is also passed into `run_validate_entry_point`, which builds the `BlockContext` for blockifier's `perform_pre_validation_stage` → `check_fee_bounds`. That check compares `resource_bounds.max_price_per_unit` against `block_info.gas_prices.gas_price_vector(fee_type).l2_gas_price` — again the wrong value: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

The EIP-1559 fee market adjusts `next_l2_gas_price` every block based on gas consumption. The divergence between `l2_gas_price` and `next_l2_gas_price` is bounded per block but accumulates across consecutive high- or low-utilization blocks.

**Case 1 — Price rising** (`next_l2_gas_price > l2_gas_price`): The gateway threshold is computed from the lower stale price. Transactions whose `max_price_per_unit` falls between `min_gas_price_percentage% × l2_gas_price` and `min_gas_price_percentage% × next_l2_gas_price` pass gateway admission but carry a gas price below what the batcher requires. These transactions enter the mempool as invalid-for-the-current-block entries. **Gateway admits transactions that should be rejected.**

**Case 2 — Price falling** (`next_l2_gas_price < l2_gas_price`): The gateway threshold is computed from the higher stale price. Transactions whose `max_price_per_unit` is sufficient for the actual block price but below the inflated threshold are rejected at the gateway. **Gateway rejects transactions that should be admitted.**

Both cases match the High impact: *Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

---

### Likelihood Explanation

The L2 gas price changes every block under normal EIP-1559 operation. Any block with gas consumption above or below the target causes `next_l2_gas_price ≠ l2_gas_price`. This is the steady-state behavior of the network, not an edge case. Any user submitting a V3 transaction (`AllResources` bounds) during a period of price movement is affected. No special privileges or adversarial setup are required — a standard `starknet_addInvokeTransaction` RPC call is sufficient to trigger either admission failure.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace the mapping of `block_header.l2_gas_price` with `block_header.next_l2_gas_price` for the `l2_gas_price` field in `GasPriceVector`. This directly resolves the TODO comment and ensures both `validate_resource_bounds` and `run_validate_entry_point` use the price that will actually govern the next block.

```rust
// Before (stale):
l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,

// After (correct):
l2_gas_price: block_header.next_l2_gas_price.try_into()?,
```

Note: `next_l2_gas_price` is a single `GasPrice` (STRK/fri only). The ETH-denominated equivalent should be derived via the current ETH→STRK conversion rate, consistent with how the batcher constructs its block context.

---

### Proof of Concept

1. Observe that block N is committed with `l2_gas_price = 100 fri` and `next_l2_gas_price = 120 fri` (price rising due to high utilization).
2. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = 110 fri`.
3. Gateway calls `validate_resource_bounds`. With `min_gas_price_percentage = 50`, threshold = `50% × 100 = 50`. The transaction passes (`110 ≥ 50`).
4. The blockifier `check_fee_bounds` in `run_validate_entry_point` also uses `l2_gas_price = 100 fri`; check passes (`110 ≥ 100`).
5. Transaction is admitted to the mempool.
6. The batcher builds block N+1 with `l2_gas_price = 120 fri` (from `next_l2_gas_price`). `check_fee_bounds` now fails: `110 < 120`. The transaction is rejected or reverts at execution.
7. The transaction occupied a mempool slot and consumed gateway validation resources despite being invalid for the block it was admitted for. [4](#0-3) [7](#0-6) [8](#0-7)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-424)
```rust
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
```
