### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Inconsistent Admission vs. Execution Fee Enforcement — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `StatefulTransactionValidator::validate_resource_bounds` function checks a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price` from the latest committed block header. However, the actual next block that will execute the transaction uses `next_l2_gas_price` (the EIP-1559-derived price stored in the same block header). These two values diverge every block. The gateway therefore admits transactions that will fail the blockifier's `check_fee_bounds` during batcher execution (when the price rose), and rejects transactions that would be valid for the next block (when the price fell). The code itself contains a `TODO` acknowledging the correct field to use.

---

### Finding Description

**Global parameter used inconsistently between two related checks:**

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, the block info returned to the gateway reads `block_header.l2_gas_price.price_in_fri` — the L2 gas price **of the latest committed block**: [1](#0-0) 

This value is then used in `validate_resource_bounds` as the reference price for the admission threshold: [2](#0-1) 

The `TODO` comment on line 229 explicitly acknowledges the bug:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The block header stores a **separate** field `next_l2_gas_price` — the EIP-1559-computed price that the consensus orchestrator will use for the **next** block: [3](#0-2) 

The consensus orchestrator writes this field when finalizing a block: [4](#0-3) 

`self.l2_gas_price` here is the value computed by `calculate_next_l2_gas_price` via the EIP-1559 fee market algorithm, which can change by up to `1/gas_price_max_change_denominator` per block: [5](#0-4) 

**The two diverging checks:**

1. **Gateway admission** (`validate_resource_bounds`): checks `tx.l2_gas.max_price_per_unit >= threshold * block_header.l2_gas_price` (current block's price).

2. **Batcher execution** (`check_fee_bounds` inside blockifier): checks `tx.l2_gas.max_price_per_unit >= block_context.l2_gas_price` where `block_context.l2_gas_price = block_header.next_l2_gas_price` (next block's price). [6](#0-5) 

The `run_validate_entry_point` in the gateway also uses the stale price (it increments only the block number, not the gas price): [7](#0-6) 

---

### Impact Explanation

**Scenario A — price rose (`next_l2_gas_price > l2_gas_price`):**

A transaction with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` passes the gateway's admission check (because it meets the threshold based on the stale price) and enters the mempool. When the batcher executes it, `check_fee_bounds` compares against the actual block price (`next_l2_gas_price`) and returns `MaxGasPriceTooLow`, causing the transaction to fail. The gateway has **admitted an invalid transaction**.

**Scenario B — price fell (`next_l2_gas_price < l2_gas_price`):**

A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price)` is **rejected by the gateway** even though it would satisfy the actual next block's fee requirement. The gateway has **rejected a valid transaction**.

Both scenarios match the High impact: *Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

---

### Likelihood Explanation

The EIP-1559 fee market adjusts the L2 gas price every block based on utilization. Under normal load variation, `next_l2_gas_price ≠ l2_gas_price` is the common case, not the exception. The divergence is bounded per block but accumulates across blocks. Any user submitting a transaction with `max_price_per_unit` close to the current price will be affected. The `min_gas_price_percentage` default of 100% means the threshold is exactly `l2_gas_price`, maximizing the window of inconsistency. [8](#0-7) 

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace the read of `block_header.l2_gas_price` with `block_header.next_l2_gas_price` when constructing the `strk_gas_prices.l2_gas_price` field returned to the gateway. This is exactly what the existing `TODO` comment requests. The same fix should be applied to `run_validate_entry_point` so that the blockifier validation at the gateway also uses the correct next-block price.

---

### Proof of Concept

1. Latest committed block N has `l2_gas_price = 10 Gwei` and `next_l2_gas_price = 11 Gwei` (price rose 10% due to high utilization).
2. User submits a transaction with `l2_gas.max_price_per_unit = 10 Gwei`.
3. Gateway `validate_resource_bounds` checks: `10 >= 100% * 10` → **passes**.
4. Transaction enters the mempool.
5. Batcher builds block N+1 with `l2_gas_price = 11 Gwei` (from `next_l2_gas_price`).
6. Blockifier `check_fee_bounds` checks: `10 >= 11` → **fails** with `MaxGasPriceTooLow`.
7. Transaction is reverted or dropped during execution despite having passed gateway admission.

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

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-425)
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
