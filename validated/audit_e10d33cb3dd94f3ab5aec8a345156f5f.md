### Title
Gateway L2 Gas Price Admission Check Uses Previous Block's Price Instead of Next Block's Price - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful admission check validates a transaction's `max_price_per_unit` for L2 gas against the **previous (last committed) block's** L2 gas price. However, the transaction will be executed in the **next** block, whose L2 gas price is computed via EIP-1559 from the previous block's gas usage and is stored as `next_l2_gas_price` in the block header. The two values diverge whenever the previous block was over or under the gas target. This causes the gateway to admit transactions that will fail at execution (price too low for the next block) and to reject transactions that would succeed (price sufficient for the next block but below the stale threshold).

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price from the latest committed block's `BlockInfo` and uses it as the admission threshold:

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
```

The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `gas_prices.strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the price **used in** the last committed block — not from `block_header.next_l2_gas_price`, which is the EIP-1559-derived price that will govern the **next** block.

The `next_l2_gas_price` is computed by `calculate_next_l2_gas_price_for_fin` / `calculate_next_base_gas_price` (EIP-1559 formula) and is stored in `StorageBlockHeader.next_l2_gas_price` and `BlockHeaderWithoutHash.next_l2_gas_price`. The batcher's `SequencerConsensusContext` maintains `self.l2_gas_price` (updated via `update_l2_gas_price` after each decision) and passes it as the block's gas price when building the next block. This is the price against which `check_fee_bounds` in `AccountTransaction::perform_pre_validation_stage` will actually reject transactions at execution time.

The same stale price is also forwarded into `run_validate_entry_point`:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
```

Only the block number is incremented; the gas prices remain those of the previous block. So both the pre-admission check and the blockifier-level gateway validation are calibrated to the wrong price.

The TODO comment at line 229 of `stateful_transaction_validator.rs` explicitly acknowledges the defect: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Impact Explanation

**Scenario A — previous block over gas target (price rising):**
`next_l2_gas_price > previous_block.l2_gas_price`. A transaction with `max_price_per_unit = previous_block.l2_gas_price` passes gateway admission and enters the mempool. When the batcher executes it, `check_fee_bounds` compares against the higher `next_l2_gas_price` and rejects with `MaxGasPriceTooLow`. The transaction was incorrectly admitted — the gateway accepted an invalid transaction.

**Scenario B — previous block under gas target (price falling):**
`next_l2_gas_price < previous_block.l2_gas_price`. A transaction with `max_price_per_unit = next_l2_gas_price` (sufficient for execution) is rejected at the gateway because it falls below `min_gas_price_percentage * previous_block.l2_gas_price`. A valid transaction is incorrectly rejected.

Both outcomes match the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The EIP-1559 L2 gas price adjusts every block based on gas usage relative to the gas target. Any block that is not exactly at the gas target produces a `next_l2_gas_price` that differs from the current block's `l2_gas_price`. Under normal network load this divergence is continuous and unprivileged — any user submitting a transaction priced at the current block's gas price will be affected. No special privileges or adversarial setup are required; the condition is triggered by ordinary network activity.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, populate the L2 gas price field from `block_header.next_l2_gas_price` (the EIP-1559-derived price for the next block) rather than `block_header.l2_gas_price.price_in_fri`. Alternatively, expose `next_l2_gas_price` as a separate field through `GatewayFixedBlockStateReader` and use it exclusively in `validate_resource_bounds` and `run_validate_entry_point`, resolving the acknowledged TODO.

---

### Proof of Concept

1. Observe that block N has `l2_gas_price = P` and `next_l2_gas_price = P'` where `P' > P` (block N was over the gas target).
2. Submit an `InvokeTransaction` (V3, `AllResources`) with `l2_gas.max_price_per_unit = P`.
3. `validate_resource_bounds` computes `threshold = min_gas_price_percentage% * P`. With `min_gas_price_percentage = 100`, threshold = `P`. The check `P >= P` passes; the transaction is admitted to the mempool.
4. The batcher builds block N+1 with `l2_gas_price = P'`. `AccountTransaction::check_fee_bounds` evaluates `resource_bounds.max_price_per_unit (P) < actual_gas_price (P')` and returns `ResourceBoundsError::MaxGasPriceTooLow`.
5. The transaction reverts or is dropped at execution despite having passed gateway admission — confirming the admission/execution price mismatch. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-330)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

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

**File:** crates/apollo_storage/src/header.rs (L84-89)
```rust
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/starknet_api/src/block.rs (L237-239)
```rust
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L496-500)
```rust
    fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
        self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
        let gas_price_u64 = u64::try_from(self.l2_gas_price.0).unwrap_or(u64::MAX);
        CONSENSUS_L2_GAS_PRICE.set_lossy(gas_price_u64);
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-476)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
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
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
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
            }
            TransactionInfo::Deprecated(context) => {
                let max_fee = context.max_fee;
                let min_fee = get_fee_by_gas_vector(
                    block_info,
                    minimal_gas_amount_vector,
                    fee_type,
                    tx_context.effective_tip(),
                );
                if max_fee < min_fee {
                    return Err(TransactionPreValidationError::TransactionFeeError(Box::new(
                        TransactionFeeError::MaxFeeTooLow { min_fee, max_fee },
                    )));
                }
            }
        };
        Ok(())
    }
```
