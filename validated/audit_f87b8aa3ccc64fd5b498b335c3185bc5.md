### Title
Gateway Stateful Validator Uses Stale Previous-Block L2 Gas Price for Resource Bounds Admission, Causing Wrong Admission Decisions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
`validate_resource_bounds` in `StatefulTransactionValidator` checks a transaction's `max_price_per_unit` against the **previous block's** (block N) L2 gas price, but the transaction will be executed in block N+1 whose L2 gas price is computed by EIP-1559 and may differ. This causes the gateway to admit transactions that will fail during execution (when the next block's price rises) or reject transactions that would succeed (when the next block's price falls). The code itself contains a TODO comment acknowledging the wrong snapshot is used.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, `validate_resource_bounds` reads gas price from `gateway_fixed_block_state_reader.get_block_info()`, which returns the latest committed block's (block N) info: [1](#0-0) 

The TODO comment at line 229 explicitly acknowledges the wrong snapshot is used:

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

The threshold check is: [2](#0-1) 

Meanwhile, `run_validate_entry_point` (called in the same flow) also calls `get_block_info()` and only increments the block number, keeping block N's gas prices: [3](#0-2) 

The actual execution in the batcher uses the real block N+1 gas prices computed by EIP-1559. The blockifier's `check_fee_bounds` in `perform_pre_validation_stage` uses the actual block context gas prices: [4](#0-3) [5](#0-4) 

The EIP-1559 price update logic that computes block N+1's price from block N's usage: [6](#0-5) 

The `GatewayFixedBlockSyncStateClient` is instantiated with the latest block number at the time of validator creation and caches the block info: [7](#0-6) 

The factory creates a fresh validator per transaction using the latest block: [8](#0-7) 

### Impact Explanation

**Accepts invalid transactions (High):** When block N+1's L2 gas price rises above block N's (full block triggers EIP-1559 increase), transactions with `max_price_per_unit` in the range `[threshold × P_N, P_{N+1})` pass gateway admission but fail `check_fee_bounds` during actual execution. The gateway has admitted a transaction that is invalid for the block it will be executed in.

**Rejects valid transactions (High):** When block N+1's L2 gas price falls below block N's (empty block), transactions with `max_price_per_unit` in the range `[P_{N+1}, threshold × P_N)` are rejected by the gateway even though they would pass `check_fee_bounds` during actual execution. Valid transactions are denied sequencing.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

EIP-1559 adjusts the L2 gas price by up to `1/gas_price_max_change_denominator` per block based on whether `gas_used > gas_target` or `gas_used < gas_target`. With the default `min_gas_price_percentage` of 100%, any block that deviates from the gas target produces a price gap between the gateway's admission threshold and the actual execution threshold. This is normal operating behavior, not an edge case. The `validate_resource_bounds` check only applies to `AllResources` (V3) transactions. [9](#0-8) 

### Recommendation

Replace the call to `get_block_info()` in `validate_resource_bounds` with a computed next-block L2 gas price using `calculate_next_l2_gas_price_for_fin` (already present in `crates/apollo_consensus_orchestrator/src/fee_market/mod.rs`), passing the previous block's gas price and its actual gas usage. This is precisely what the existing TODO comment requests.

### Proof of Concept

**Admits invalid transaction:**
1. Block N has L2 gas price P = 1000 fri and is full (`gas_used > gas_target`).
2. EIP-1559 computes block N+1's gas price P' = 1100 fri.
3. User submits a V3 invoke with `l2_gas.max_price_per_unit = 1000 fri`.
4. Gateway `validate_resource_bounds`: `1000 >= 100% × 1000` → **admitted**.
5. Batcher includes the transaction in block N+1.
6. Blockifier `check_fee_bounds`: `1000 >= 1100` → **fails**, transaction reverts.

**Rejects valid transaction:**
1. Block N has L2 gas price P = 1000 fri and is empty (`gas_used < gas_target`).
2. EIP-1559 computes block N+1's gas price P' = 900 fri.
3. User submits a V3 invoke with `l2_gas.max_price_per_unit = 950 fri`.
4. Gateway `validate_resource_bounds`: `950 >= 100% × 1000` → **rejected**.
5. The transaction would have passed `check_fee_bounds` in block N+1 (`950 >= 900`).

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L86-119)
```rust
    async fn instantiate_validator(
        &self,
        native_classes_whitelist: NativeClassesWhitelist,
    ) -> StatefulTransactionValidatorResult<Box<Self::Validator>> {
        // TODO(yael 6/5/2024): consider storing the block_info as part of the
        // StatefulTransactionValidator and update it only once a new block is created.
        let (blockifier_state_reader, gateway_fixed_block_state_reader) = self
            .state_reader_factory
            .get_blockifier_state_reader_and_gateway_fixed_block_from_latest_block()
            .await
            .map_err(|err| GatewaySpecError::UnexpectedError {
                data: format!("Internal server error: {err}"),
            })
            .map_err(|e| {
                StarknetError::internal_with_logging(
                    "Failed to get state reader from latest block",
                    e,
                )
            })?;
        let state_reader_and_contract_manager =
            StateReaderAndContractManager::new_with_native_classes_whitelist(
                blockifier_state_reader,
                self.contract_class_manager.clone(),
                native_classes_whitelist,
                Some(GATEWAY_CLASS_CACHE_METRICS),
            );

        Ok(Box::new(StatefulTransactionValidator::new(
            self.config.clone(),
            self.chain_info.clone(),
            state_reader_and_contract_manager,
            gateway_fixed_block_state_reader,
        )))
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L363-366)
```rust
        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-400)
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
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-140)
```rust
pub fn calculate_next_base_gas_price(
    price: GasPrice,
    gas_used: GasAmount,
    gas_target: GasAmount,
    min_gas_price: GasPrice,
) -> GasPrice {
    let versioned_constants = VersionedConstants::latest_constants();
    assert!(
        gas_target < versioned_constants.max_block_size,
        "Gas target must be lower than max block size."
    );
    assert!(gas_target.0 > 0, "Gas target must be greater than zero.");
    assert!(
        versioned_constants.gas_price_max_change_denominator > 0,
        "Denominator constant must be greater than zero."
    );

    // If the current price is below the minimum, apply a gradual adjustment and return early.
    // This allows the price to increase by at most 1/MIN_GAS_PRICE_INCREASE_DENOMINATOR per block.
    if price < min_gas_price {
        let max_increase = price.0 / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let adjusted = price.0 + max_increase;
        // Cap at min_gas_price to avoid overshooting
        let adjusted_price = adjusted.min(min_gas_price.0);
        info!(
            "Fee Market: Price {} below minimum gas price {}, adjusted price: {} )",
            price.0, min_gas_price.0, adjusted_price
        );
        return GasPrice(adjusted_price);
    }

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
}
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-67)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}

impl GatewayFixedBlockSyncStateClient {
    pub fn new(state_sync_client: SharedStateSyncClient, block_number: BlockNumber) -> Self {
        Self { state_sync_client, block_number, block_info_cache: OnceCell::new() }
    }

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
}

#[async_trait]
impl GatewayFixedBlockStateReader for GatewayFixedBlockSyncStateClient {
    async fn get_block_info(&self) -> StarknetResult<BlockInfo> {
        self.block_info_cache
            .get_or_try_init(|| self.get_block_info_from_sync_client())
            .await
            .cloned()
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-300)
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
}
```
