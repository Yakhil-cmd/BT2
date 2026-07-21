### Title
Gateway Stateful Validator Checks L2 Gas Price Against Current Block's Price Instead of `next_l2_gas_price`, Causing Wrong Admission and Rejection Decisions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `gas_prices.strk_gas_prices.l2_gas_price` from the latest block's `BlockInfo` as the threshold for the incoming transaction's `max_price_per_unit`. However, the transaction will be sequenced into the **next** block, whose gas price is `next_l2_gas_price` (a distinct field in `BlockHeaderWithoutHash`, computed via EIP-1559). The code itself acknowledges this with a developer TODO. Using the current block's price as the threshold is the same class of unit/domain mismatch as the external report's use of debt shares where debt assets were required: a value from one accounting epoch is substituted for a value from the correct epoch, corrupting the admission decision.

---

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` fetches the latest block's `BlockInfo` and extracts `strk_gas_prices.l2_gas_price` as the reference price:

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

`validate_tx_l2_gas_price_within_threshold` then computes `threshold = previous_block_l2_gas_price * min_gas_price_percentage / 100` and rejects the transaction if `tx.l2_gas.max_price_per_unit < threshold`: [2](#0-1) 

The block header carries a separate `next_l2_gas_price` field — the EIP-1559-adjusted price that will govern the **next** block: [3](#0-2) 

`next_l2_gas_price` is computed by `calculate_next_base_gas_price` from the current block's gas usage and price: [4](#0-3) 

The two values diverge whenever the block is not exactly at the gas target. The `BlockInfo` struct returned by `get_block_info()` does not expose `next_l2_gas_price`; the gateway therefore has no path to the correct value and silently falls back to the stale one.

The same stale price is also propagated into `run_validate_entry_point`, which builds a `BlockContext` from the same `block_info` (with only the block number incremented) and runs the blockifier's `check_fee_bounds` against it: [5](#0-4) 

The batcher, by contrast, builds its `BlockContext` from the `ProposalInit` which carries the freshly computed `next_l2_gas_price`. So the gateway's blockifier simulation and the batcher's actual execution use different gas prices for the same transaction.

---

### Impact Explanation

**Wrong admission (gas price rising):** When `next_l2_gas_price > l2_gas_price`, a transaction whose `max_price_per_unit` satisfies `l2_gas_price ≤ max_price_per_unit < next_l2_gas_price` passes both the gateway's threshold check and its blockifier simulation (both use the stale lower price), is admitted to the mempool, and is then rejected by the batcher's blockifier with `MaxGasPriceTooLow` during `perform_pre_validation_stage`. The transaction cannot be included in any block and is permanently stuck in the mempool.

**Wrong rejection (gas price falling):** When `next_l2_gas_price < l2_gas_price`, a transaction whose `max_price_per_unit` satisfies `next_l2_gas_price ≤ max_price_per_unit < l2_gas_price` is rejected at the gateway with `GAS_PRICE_TOO_LOW` even though it would be perfectly valid for the next block.

Both outcomes match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The EIP-1559 formula adjusts the price by up to `1/gas_price_max_change_denominator` per block. With the default denominator the per-block swing is small but non-zero on every block where gas usage differs from the target. Any user who submits a transaction priced at exactly the current block's gas price (a natural choice) triggers the wrong-admission path whenever the price is rising. No special privilege is required; the trigger is a normal transaction submission.

---

### Recommendation

Replace the `l2_gas_price` read with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait should expose a method (or the existing `get_block_info` should be extended) to return `BlockHeaderWithoutHash::next_l2_gas_price`. The same corrected price should be injected into the `BlockInfo` passed to `run_validate_entry_point` so that the gateway's blockifier simulation matches the batcher's execution context.

---

### Proof of Concept

1. Observe the current block's `l2_gas_price` = P and `next_l2_gas_price` = P′ where P′ > P (any block with gas usage above target).
2. Submit an invoke transaction with `AllResourceBounds { l2_gas: { max_price_per_unit: P, max_amount: X }, … }`.
3. `validate_tx_l2_gas_price_within_threshold` computes `threshold = P * 100% = P`; the check `P < P` is false → transaction passes.
4. `run_validate_entry_point` builds `BlockContext` with `gas_prices.strk_gas_prices.l2_gas_price = P`; `check_fee_bounds` checks `P < P` → false → blockifier validation passes.
5. Transaction is admitted to the mempool.
6. Batcher builds `BlockContext` from `ProposalInit` with `l2_gas_price = P′`; `check_fee_bounds` checks `P < P′` → true → `MaxGasPriceTooLow` → transaction is rejected by the batcher and never included in a block.

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
