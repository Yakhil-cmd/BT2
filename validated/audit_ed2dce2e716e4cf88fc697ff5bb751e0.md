### Title
Gateway Stateful Validator Admits Transactions Using Stale Previous-Block L2 Gas Price, Causing Mempool Admission of Transactions That Will Fail Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `StatefulTransactionValidator` uses the **previous block's** L2 gas price as the reference for both its threshold admission check and its blockifier pre-validation. The batcher executes transactions against the **current block's** gas prices. When the L2 gas price rises sharply between blocks, transactions whose `max_price_per_unit` sits above the stale threshold but below the actual next-block price pass all gateway checks and enter the mempool, yet are guaranteed to fail at execution time with `MaxGasPriceTooLow`. An unprivileged user can exploit this window deliberately to flood the mempool with economically-invalid transactions.

### Finding Description

**Root cause — stale price in `validate_resource_bounds`**

`validate_resource_bounds` fetches the block info from `gateway_fixed_block_state_reader.get_block_info()`, which returns the **latest committed block** (i.e., the previous block, not the pending/next block). The TODO comment on line 229 explicitly acknowledges this is wrong:

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

The threshold is computed as `(min_gas_price_percentage / 100) * previous_block_l2_gas_price`. A transaction passes if `tx.l2_gas.max_price_per_unit >= threshold`. [2](#0-1) 

**Root cause — same stale price in `run_validate_entry_point`**

The blockifier pre-validation run inside the gateway also builds its `BlockContext` from the same stale `get_block_info()` call (only the block number is incremented; gas prices are unchanged):

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

So `check_fee_bounds` inside `perform_pre_validation_stage` also runs against the old price and passes. [4](#0-3) 

**Root cause — `OnceCell` cache in `GatewayFixedBlockSyncStateClient`**

The `block_info_cache` is a `OnceCell<BlockInfo>`, meaning the block info is fetched exactly once per validator instance and never refreshed. The validator is instantiated per transaction via `instantiate_validator`, so the cache is always the latest committed block at the moment of instantiation — never the pending/next block. [5](#0-4) 

**Root cause — `L1Gas` legacy transactions bypass the L2 gas price check entirely**

`validate_tx_l2_gas_price_within_threshold` contains an explicit no-op branch for `ValidResourceBounds::L1Gas`:

```rust
ValidResourceBounds::L1Gas(_) => {
    // No validation required for legacy transactions.
}
``` [6](#0-5) 

Legacy V3 transactions with `L1Gas` bounds therefore receive zero L2 gas price scrutiny at the gateway, regardless of how low their `max_price_per_unit` is.

**Divergence at execution time**

When the batcher executes the transaction, `check_fee_bounds` uses the **current block's** gas prices (set by the consensus orchestrator for the new block). If the L2 gas price has risen since the previous block, the condition `resource_bounds.max_price_per_unit < actual_gas_price.get()` fires and the transaction fails with `InsufficientResourceBounds { MaxGasPriceTooLow }`. [7](#0-6) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's two-stage stateful check (threshold check + blockifier pre-validation) both use the previous block's L2 gas price. A transaction that passes both checks is forwarded to the mempool and eventually handed to the batcher. If the L2 gas price has risen by the time the batcher builds the next block, the transaction fails at `perform_pre_validation_stage` inside the batcher, wasting sequencer resources and polluting the mempool with economically-invalid entries.

The inverse also holds: when the L2 gas price drops sharply, the stale threshold is too high, causing valid transactions (whose `max_price_per_unit` covers the actual next-block price) to be incorrectly rejected at the gateway.

### Likelihood Explanation

The L2 gas price is computed by an EIP-1559-style mechanism that adjusts each block based on gas usage. During periods of high network activity the price can increase by a non-trivial percentage per block. The window between gateway validation and batcher execution spans at least one block boundary. Any user who observes the previous block's L2 gas price and sets `max_price_per_unit` to exactly the stale threshold will reliably trigger this condition whenever the price rises. No privileged access is required; a standard `invoke_v3` transaction with `AllResources` bounds suffices.

### Recommendation

1. **Use the next block's projected L2 gas price** in `validate_resource_bounds` and `run_validate_entry_point`. The consensus orchestrator already computes the next block's L2 gas price before building a proposal; expose it to the gateway (the existing TODO at line 229 points in this direction).
2. **Apply the threshold check to all resource types**, not only `AllResources`. The current `L1Gas` no-op branch means legacy transactions are entirely unguarded.
3. **Refresh the cached block info** more aggressively, or replace the `OnceCell` with a value that is updated when a new block is committed, so the gateway always validates against the most recent committed prices.

### Proof of Concept

1. Observe the current committed block's STRK L2 gas price: `P_prev`.
2. Compute the gateway admission threshold: `T = floor(min_gas_price_percentage * P_prev / 100)`.
3. Craft an `invoke_v3` transaction with `AllResources` bounds where `l2_gas.max_price_per_unit = T` (just at the threshold).
4. Submit the transaction to the gateway. Both checks pass because they use `P_prev`.
5. The transaction enters the mempool.
6. The batcher builds the next block with `P_next > T` (e.g., after a burst of high-gas-usage transactions in the previous block).
7. `check_fee_bounds` inside `perform_pre_validation_stage` evaluates `T < P_next` → `MaxGasPriceTooLow` → transaction fails at execution.
8. Repeat at high frequency to saturate the mempool with transactions that always fail execution, degrading sequencer throughput without any on-chain cost to the attacker (failed pre-validation transactions are not included in blocks and do not pay fees). [1](#0-0) [2](#0-1) [8](#0-7) [4](#0-3)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
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
