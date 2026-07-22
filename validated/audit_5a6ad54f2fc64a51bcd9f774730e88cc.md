### Title
Gateway Stateful Admission Checks Transaction L2 Gas Price Against Stale `l2_gas_price` Instead of `next_l2_gas_price` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will be executed in the **next block** at `next_l2_gas_price` (the EIP-1559-adjusted price stored in the block header). When gas usage is above target, `next_l2_gas_price > l2_gas_price`, so the gateway admits transactions that will fail `check_fee_bounds` during actual blockifier execution. The code even carries a developer TODO acknowledging the wrong field is used.

---

### Finding Description

`validate_resource_bounds` reads the block info from `GatewayFixedBlockSyncStateClient`, which maps `block_header.l2_gas_price` into the returned `BlockInfo`: [1](#0-0) 

The validator then uses that value as the admission threshold: [2](#0-1) 

The TODO comment on line 229 explicitly acknowledges the wrong field is used. The block header stores two distinct prices:

- `l2_gas_price` — the price **of the current block** (already settled)
- `next_l2_gas_price` — the EIP-1559-adjusted price **for the next block** (what execution will actually use) [3](#0-2) 

`next_l2_gas_price` is computed via `calculate_next_base_gas_price` and rises whenever gas usage exceeds the target: [4](#0-3) 

The batcher sends the actual execution-block gas price to the mempool: [5](#0-4) 

The blockifier's `check_fee_bounds` then enforces the real block gas price during execution: [6](#0-5) 

`run_validate_entry_point` also builds its block context from the same stale `get_block_info()` call (only incrementing the block number, not the gas price), so the gateway's own blockifier pre-validation also passes at the wrong price: [7](#0-6) 

**Attack path:**

1. Attacker observes current block's `l2_gas_price = P` and `next_l2_gas_price = P'` where `P' > P` (high-usage block).
2. Attacker submits a transaction with `max_price_per_unit = P` (or any value in `[P, P')`).
3. Gateway admission check compares against `P` → passes.
4. Transaction enters the mempool.
5. Batcher builds the next block at price `P'`; blockifier `check_fee_bounds` rejects the transaction because `max_price_per_unit < P'`.
6. Transaction is dropped from execution but was already admitted, consuming mempool slots and gateway processing resources.

---

### Impact Explanation

Transactions that will deterministically fail `check_fee_bounds` during blockifier execution are admitted through the gateway and mempool. This breaks the admission invariant: the gateway should reject any transaction whose `max_price_per_unit` is below the price at which it will actually be executed. The corrupted value is the admission decision itself — a "valid" gateway response for a transaction that cannot execute.

---

### Likelihood Explanation

This triggers whenever `next_l2_gas_price > l2_gas_price`, which occurs in every block where L2 gas consumption exceeds the EIP-1559 target. With `min_gas_price_percentage = 100` (the production default), a transaction setting `max_price_per_unit` exactly equal to the current block's `l2_gas_price` will always be admitted and always fail execution when the price is rising. No privileged access is required; any user can observe the on-chain prices and craft such a transaction.

---

### Recommendation

Replace the `l2_gas_price` field read in `validate_resource_bounds` with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait and `GatewayFixedBlockSyncStateClient` should expose `next_l2_gas_price` (already present in `BlockHeaderWithoutHash`) so the threshold reflects the price at which the transaction will actually be executed. The same correction should be applied to the `block_info` passed into `run_validate_entry_point`.

---

### Proof of Concept

```
Block N committed with:
  l2_gas_price        = 1_000_000_000  (1 Gwei)
  next_l2_gas_price   = 1_003_003_003  (EIP-1559 +0.3% due to high usage)

Attacker submits InvokeV3 with:
  resource_bounds.l2_gas.max_price_per_unit = 1_000_000_000

Gateway validate_resource_bounds:
  threshold = 1_000_000_000 * 100% = 1_000_000_000
  tx_l2_gas_price (1_000_000_000) >= threshold → ADMITTED

Batcher builds block N+1 at l2_gas_price = 1_003_003_003:
  check_fee_bounds:
    resource_bounds.max_price_per_unit (1_000_000_000)
      < actual_gas_price (1_003_003_003)
    → ResourceBoundsError::MaxGasPriceTooLow → transaction DROPPED

Result: gateway admitted a transaction that blockifier rejects.
``` [8](#0-7) [9](#0-8)

### Citations

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

**File:** crates/apollo_storage/src/header.rs (L84-89)
```rust
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/apollo_batcher/src/batcher.rs (L371-383)
```rust
        info!(
            "Updating gas price for block {}, round {} in Mempool client",
            block_number, propose_block_input.proposal_round
        );
        mempool_client
            .update_gas_price(
                propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
            )
            .await
            .map_err(|err| {
                error!("Failed to update gas price in mempool: {}", err);
                BatcherError::InternalError
            })?;
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
