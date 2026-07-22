### Title
Gateway Stateful Validator Uses Wrong L2 Gas Price Field for Resource-Bounds Threshold — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `gas_prices.strk_gas_prices.l2_gas_price` from the last committed block's `BlockInfo` as the reference price for the admission threshold. The correct reference is `next_l2_gas_price` stored in the same block header — the EIP-1559-adjusted price that the batcher will actually use when executing the next block. Because these two fields diverge whenever a block is over- or under-utilized, the gateway applies the wrong threshold, causing valid transactions to be rejected and invalid transactions to be admitted.

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` fetches the previous block's `BlockInfo` and extracts `strk_gas_prices.l2_gas_price`: [1](#0-0) 

The code itself carries an explicit acknowledgement of the error:

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

`BlockInfo.gas_prices.strk_gas_prices.l2_gas_price` is the price **of** block N — the price that was in effect when block N was built. `StorageBlockHeader.next_l2_gas_price` is the EIP-1559-derived price **for** block N+1, computed from block N's actual gas consumption: [2](#0-1) 

The consensus orchestrator updates `self.l2_gas_price` to `next_l2_gas_price` after each decision and embeds it in `ProposalInit.l2_gas_price_fri`: [3](#0-2) 

The batcher then builds the block context for execution using that value, so `check_fee_bounds` inside `perform_pre_validation_stage` enforces `tx.max_price_per_unit >= next_l2_gas_price`: [4](#0-3) 

The gateway's `GatewayFixedBlockSyncStateClient.get_block_info()` constructs `BlockInfo` from `block_header.l2_gas_price.price_in_fri`, which is the **current** block's price, not `next_l2_gas_price`: [5](#0-4) 

`next_l2_gas_price` is not exposed through the `BlockInfo` struct at all, so the correct value is structurally inaccessible to `validate_resource_bounds` through the current interface.

### Impact Explanation

Two divergent admission outcomes arise:

**False rejection (valid tx denied):** When block N is under-utilized, EIP-1559 lowers the price: `next_l2_gas_price < l2_gas_price`. A transaction with `max_price ∈ [next_l2_gas_price, l2_gas_price)` satisfies the blockifier's actual fee check but fails the gateway threshold. The user's valid transaction is permanently rejected at the gateway.

**False acceptance (invalid tx admitted):** When block N is over-utilized, EIP-1559 raises the price: `next_l2_gas_price > l2_gas_price`. A transaction with `max_price ∈ [l2_gas_price, next_l2_gas_price)` passes the gateway threshold but will fail `check_fee_bounds` during block building. The transaction enters the mempool and can never be sequenced.

Both outcomes match the allowed High impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 formula adjusts the price every block based on gas usage relative to `gas_target`: [6](#0-5) 

Any block that deviates from the target (which is the common case under variable load) produces `next_l2_gas_price ≠ l2_gas_price`. The discrepancy is bounded per block but accumulates across consecutive over- or under-utilized blocks. No special privileges are required — any user submitting a V3 (`AllResources`) transaction when `validate_resource_bounds = true` and `min_gas_price_percentage > 0` is affected.

### Recommendation

Replace the `l2_gas_price` field read with `next_l2_gas_price` from the block header. This requires:

1. Extending `GatewayFixedBlockStateReader::get_block_info` (or adding a new method) to return `next_l2_gas_price` from `StorageBlockHeader`/`BlockHeaderWithoutHash`.
2. Updating `validate_resource_bounds` to use that value as the reference price.

The TODO comment in the code already identifies the correct fix: `// TODO(Arni): getnext_l2_gas_price from the block header.`

### Proof of Concept

1. Observe block N with `l2_gas_price = 100` and low utilization, so `next_l2_gas_price = 90` (EIP-1559 decrease).
2. Configure gateway with `validate_resource_bounds = true`, `min_gas_price_percentage = 100`.
3. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = 95`.
4. Gateway computes threshold = `100% × 100 = 100`; rejects the transaction with `GAS_PRICE_TOO_LOW` because `95 < 100`.
5. The blockifier would compute threshold = `next_l2_gas_price = 90`; the transaction satisfies `95 >= 90` and would be accepted.
6. A valid transaction is permanently denied at the gateway admission layer.

Conversely, with block N over-utilized (`next_l2_gas_price = 110`), a transaction with `max_price = 105` passes the gateway (`105 >= 100`) but fails blockifier execution (`105 < 110`), entering the mempool in an un-sequenceable state.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-240)
```rust
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
```

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L496-500)
```rust
    fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
        self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
        let gas_price_u64 = u64::try_from(self.l2_gas_price.0).unwrap_or(u64::MAX);
        CONSENSUS_L2_GAS_PRICE.set_lossy(gas_price_u64);
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
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
