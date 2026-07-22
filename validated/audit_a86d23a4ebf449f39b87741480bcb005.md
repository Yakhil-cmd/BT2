### Title
Gateway L2 Gas Price Validation Uses Wrong Block Reference, Admitting Transactions That Fail at Execution and Rejecting Transactions That Would Succeed — (`crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs` / `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful validator checks a transaction's L2 gas price against the **current (previous) block's** `l2_gas_price`, but the transaction will be executed in the **next block** whose L2 gas price is stored separately as `next_l2_gas_price` in the same block header. The `next_l2_gas_price` field is available in `BlockHeaderWithoutHash` and is explicitly computed by the EIP-1559 fee-market algorithm, yet `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` silently ignores it. This causes the gateway to admit transactions that will fail at execution (when the price is rising) and to reject transactions that would succeed (when the price is falling). The code itself contains a TODO acknowledging the wrong reference: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Finding Description

**Root cause — wrong field read in `get_block_info_from_sync_client`**

`GatewayFixedBlockSyncStateClient` builds a `BlockInfo` from the latest committed block header. It populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the price that was in effect *for the block that was just committed* — while ignoring `block_header.next_l2_gas_price`, which is the price the fee-market algorithm computed for the *next* block and stored in the header for exactly this purpose. [1](#0-0) 

The `next_l2_gas_price` field is present in `BlockHeaderWithoutHash` and is written by the consensus orchestrator at decision time: [2](#0-1) 

It is also stored in `StorageBlockHeader`: [3](#0-2) 

**First propagation — `validate_resource_bounds`**

`validate_resource_bounds` reads the `BlockInfo` produced above and uses its `strk_gas_prices.l2_gas_price` (the *current* block's price) as the reference for the threshold check. The TODO comment in the code explicitly flags this as wrong: [4](#0-3) 

The threshold is computed as `prev_block_l2_gas_price * min_gas_price_percentage / 100`. With the default `min_gas_price_percentage = 100`, the threshold equals the previous block's price exactly. [5](#0-4) 

**Second propagation — `run_validate_entry_point`**

The blockifier validation inside the gateway increments `block_number` to simulate the next block but leaves `gas_prices` unchanged (still the previous block's prices). The `check_fee_bounds` call inside `perform_pre_validation_stage` therefore compares the transaction's `max_price_per_unit` against the *previous* block's gas prices, not the next block's: [6](#0-5) [7](#0-6) 

The `check_fee_bounds` comparison that will fire at actual execution time: [8](#0-7) 

---

### Impact Explanation

**Case 1 — gas price rising (blocks are full, EIP-1559 pushes price up):**

Let `P` = previous block's L2 gas price, `P'` = next block's L2 gas price (`P' > P`).

A transaction with `tx_l2_gas_price` in `[P, P')`:
- Passes `validate_resource_bounds` (≥ threshold `P * 100%`).
- Passes the gateway's blockifier `check_fee_bounds` (uses `P` as reference).
- Is admitted to the mempool.
- **Fails at actual execution** with `MaxGasPriceTooLow` because the batcher uses `P'` as the block's gas price.

**Case 2 — gas price falling (blocks are empty, EIP-1559 pushes price down):**

Let `P` = previous block's price, `P'` = next block's price (`P' < P`).

A transaction with `tx_l2_gas_price` in `[P' * threshold, P * threshold)`:
- **Rejected by the gateway** (below threshold `P * threshold`).
- Would have **passed at actual execution** (≥ `P'`).

Both cases match the impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The EIP-1559 fee market (`calculate_next_base_gas_price`) adjusts the L2 gas price every block based on utilization. Any deviation from the target gas usage causes `next_l2_gas_price ≠ l2_gas_price`. This is the normal operating condition, not an edge case. The discrepancy is bounded per block by `price / gas_price_max_change_denominator`, but it is persistent and cumulative during sustained high or low utilization. Any V3 (`AllResources`) transaction submitted during such a period is affected. [9](#0-8) 

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace `block_header.l2_gas_price.price_in_fri` with `block_header.next_l2_gas_price` when populating the STRK L2 gas price used for gateway validation. Alternatively, expose `next_l2_gas_price` as a separate field on `GatewayFixedBlockStateReader` and use it directly in `validate_resource_bounds` and as the L2 gas price in the `BlockContext` built inside `run_validate_entry_point`. This resolves the TODO already present in the code and aligns the gateway's admission decision with the price that will actually be enforced at execution time.

---

### Proof of Concept

1. Observe that `BlockHeaderWithoutHash` carries both `l2_gas_price` (current block) and `next_l2_gas_price` (next block). The consensus orchestrator writes `next_l2_gas_price: self.l2_gas_price` (the EIP-1559-adjusted price) into every committed block header. [10](#0-9) 

2. `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` reads `block_header.l2_gas_price.price_in_fri` and ignores `block_header.next_l2_gas_price`. [11](#0-10) 

3. Submit a V3 `AllResources` invoke transaction with `l2_gas.max_price_per_unit = P` (the current block's L2 gas price in fri) during a period of sustained high block utilization where `next_l2_gas_price = P' > P`.

4. `validate_resource_bounds` computes threshold = `P * 100 / 100 = P`. Since `tx_price = P ≥ P`, the check passes. [12](#0-11) 

5. `run_validate_entry_point` builds a `BlockContext` with `block_number = prev+1` but `gas_prices.strk_gas_prices.l2_gas_price = P`. `check_fee_bounds` passes because `P ≥ P`. The transaction is admitted to the mempool. [13](#0-12) 

6. When the batcher executes the transaction in the next block, it uses `gas_prices.strk_gas_prices.l2_gas_price = P'`. `check_fee_bounds` now finds `tx_price P < P'` and returns `MaxGasPriceTooLow`, causing the transaction to fail — despite having been explicitly admitted by the gateway. [8](#0-7)

### Citations

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

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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
