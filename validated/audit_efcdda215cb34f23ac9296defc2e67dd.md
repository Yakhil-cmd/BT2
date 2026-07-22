### Title
Gateway L2 Gas Price Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Systematic Admission/Rejection Inversion - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validator checks a transaction's `max_price_per_unit` against the **previous block's `l2_gas_price`** field, but the batcher builds the next block using **`next_l2_gas_price`** (the EIP-1559-adjusted price computed from the previous block's gas consumption). When these two values diverge — which is the normal case whenever gas usage deviates from the target — the gateway admits transactions that the batcher will reject, and rejects transactions that the batcher would accept.

### Finding Description

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

- `l2_gas_price`: the price **used inside** the committed block for fee charging.
- `next_l2_gas_price`: the EIP-1559-adjusted price **to be used in the next block**, computed from `l2_gas_consumed` via `calculate_next_base_gas_price`. [1](#0-0) 

When a block is committed, `update_state_sync_with_new_block` stores `self.l2_gas_price` (the sequencer's current price for the **next** block) as `next_l2_gas_price` in the header, and the batcher subsequently uses that value as the actual gas price for block N+1. [2](#0-1) 

`try_sync` confirms this: when syncing, the context reads `next_l2_gas_price` from the committed block header and sets it as `self.l2_gas_price` for the next block to be built. [3](#0-2) 

The gateway's `validate_resource_bounds`, however, reads `get_block_info()` which populates `gas_prices.strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price` — the **current** block's price, not `next_l2_gas_price`. The TODO comment in the code explicitly acknowledges this is wrong: [4](#0-3) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` reads `block_header.l2_gas_price` (not `next_l2_gas_price`) when constructing the `BlockInfo` returned to the validator: [5](#0-4) 

The same stale price is also used in `run_validate_entry_point` when building the `BlockContext` for blockifier validation at the gateway: [6](#0-5) 

The blockifier's `check_fee_bounds` inside `perform_pre_validation_stage` enforces `max_price_per_unit >= actual_gas_price` using the **block context's** gas price — which at the batcher is `next_l2_gas_price`, not `l2_gas_price`: [7](#0-6) 

**Concrete divergence scenario (rising price):**

Block N is committed with `l2_gas_price = P` and `next_l2_gas_price = P'` where `P' > P` (gas usage exceeded the EIP-1559 target). The gateway validates transactions for block N+1 using `P`. A transaction with `max_price_per_unit = P` passes both the threshold check (`P >= 100% × P`) and the gateway's blockifier validation (which also uses `P` as the block gas price). The batcher builds block N+1 with gas price `P'`. The blockifier's `check_fee_bounds` fails: `P < P'`. The transaction is rejected.

**Concrete divergence scenario (falling price):**

Block N has `next_l2_gas_price = P'` where `P' < P`. A transaction with `max_price_per_unit = P'` is valid for block N+1 (since `P' >= P'`) but the gateway rejects it because `P' < 100% × P`.

The EIP-1559 formula allows up to `1/gas_price_max_change_denominator` change per block. Under sustained high load the cumulative drift between `l2_gas_price` and `next_l2_gas_price` can be significant. [8](#0-7) 

### Impact Explanation

The gateway systematically admits transactions that will be rejected by the batcher (when price is rising) and rejects transactions that would be accepted by the batcher (when price is falling). This is a **High** impact issue matching: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Admitted-but-rejected transactions consume mempool slots, waste batcher execution cycles, and cause user-visible failures after the transaction was already accepted. Rejected-but-valid transactions cause users to receive spurious `GAS_PRICE_TOO_LOW` errors for transactions that would have executed successfully.

### Likelihood Explanation

The condition is triggered whenever the previous block's gas consumption deviates from the EIP-1559 target — which is the normal operating condition for any non-trivially loaded network. No privileged access is required; any user submitting a transaction priced at the previous block's `l2_gas_price` triggers the mismatch.

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace `block_header.l2_gas_price` with `block_header.next_l2_gas_price` when populating the `l2_gas_price` field of the returned `BlockInfo`. Since `next_l2_gas_price` is currently FRI-only, the WEI equivalent must also be derived (e.g., via the stored ETH/STRK conversion rate). This is the fix the existing TODO comment points toward:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The same correction must be applied to `run_validate_entry_point` so that the blockifier validation at the gateway uses the same gas price the batcher will use.

### Proof of Concept

1. Observe block N with `l2_gas_price = 1000 fri` and `next_l2_gas_price = 1125 fri` (gas usage 12.5% above target, within EIP-1559 bounds).
2. Submit an invoke V3 transaction with `l2_gas.max_price_per_unit = 1000 fri`.
3. Gateway's `validate_resource_bounds` computes threshold = `100% × 1000 = 1000`; `1000 >= 1000` → **admitted**.
4. Gateway's `run_validate_entry_point` builds `BlockContext` with `l2_gas_price = 1000 fri`; `check_fee_bounds` passes `1000 >= 1000` → **admitted to mempool**.
5. Batcher builds block N+1 with `l2_gas_price = 1125 fri` (from `next_l2_gas_price`).
6. Blockifier's `check_fee_bounds` evaluates `1000 < 1125` → `MaxGasPriceTooLow` → **transaction rejected during block building**. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L1055-1059)
```rust
        // May be default for blocks older than 0.14.0, ensure min gas price is met.
        self.l2_gas_price = max(
            sync_block.block_header_without_hash.next_l2_gas_price,
            VersionedConstants::latest_constants().min_gas_price,
        );
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
