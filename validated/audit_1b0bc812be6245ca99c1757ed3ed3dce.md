### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Admitting Transactions That Will Fail Execution — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check validates a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the next block to be built will execute at `next_l2_gas_price` (the EIP-1559-adjusted price stored in the same block header). The two values diverge whenever blocks are not exactly at the gas target. During sustained congestion, `next_l2_gas_price` can be materially higher than `l2_gas_price`. Transactions whose `max_price_per_unit` falls in the gap `[l2_gas_price, next_l2_gas_price)` pass gateway admission but are rejected by the blockifier's `check_fee_bounds` pre-validation with `ResourceBoundsError::MaxGasPriceTooLow`. The inverse holds when the network is uncongested: transactions priced correctly for the next block are rejected by the gateway even though they would succeed in execution.

---

### Finding Description

**Root cause — wrong field read in `validate_resource_bounds`:**

`StatefulTransactionValidator::validate_resource_bounds` reads the reference price from `GatewayFixedBlockStateReader::get_block_info()`:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
``` [1](#0-0) 

The `BlockInfo` struct returned by `get_block_info()` is populated from `block_header.l2_gas_price` — the price that was used **inside** the already-committed block:

```rust
l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
``` [2](#0-1) 

**The correct field is `next_l2_gas_price`**, which is a separate field in `BlockHeaderWithoutHash` and is set by the consensus orchestrator after every decided block:

```rust
let block_header_without_hash = BlockHeaderWithoutHash {
    l2_gas_price,                          // price used IN this block
    next_l2_gas_price: self.l2_gas_price,  // price for the NEXT block
    ...
};
``` [3](#0-2) 

`next_l2_gas_price` is computed by the EIP-1559 `calculate_next_base_gas_price` function and stored in `BlockHeaderWithoutHash`: [4](#0-3) 

The `BlockInfo` struct that `GatewayFixedBlockSyncStateClient` builds does **not** include `next_l2_gas_price`; it only maps `l2_gas_price`. The TODO comment in the validator explicitly acknowledges the missing field.

**How the blockifier enforces the correct price:**

During execution, `AccountTransaction::perform_pre_validation_stage` / `check_fee_bounds` checks:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
```

where `actual_gas_price` is taken from the **block context's** `gas_prices` — which is set to `next_l2_gas_price` for the block being built. [5](#0-4) 

**The gap:**

| Condition | Gateway decision | Blockifier decision |
|---|---|---|
| `max_price ≥ next_l2_gas_price` | Accept | Accept ✓ |
| `l2_gas_price ≤ max_price < next_l2_gas_price` (congestion) | **Accept** | **Reject** ✗ |
| `next_l2_gas_price ≤ max_price < l2_gas_price` (post-congestion) | **Reject** | **Accept** ✗ |

---

### Impact Explanation

**Admission of invalid transactions (congested network):** When blocks are consistently full, the EIP-1559 mechanism raises `next_l2_gas_price` above `l2_gas_price`. Any transaction with `max_price_per_unit` in `[l2_gas_price, next_l2_gas_price)` passes the gateway threshold check but is rejected by the blockifier with `InsufficientResourceBounds`. These transactions occupy mempool slots and consume batcher execution resources without ever being included in a block.

**Rejection of valid transactions (post-congestion):** When blocks become empty after a congested period, `next_l2_gas_price` drops below `l2_gas_price`. Transactions priced correctly for the next block are rejected at the gateway even though they would succeed in execution. This is a liveness failure for users who price their transactions based on the current (lower) gas price.

Both cases match: **High — Mempool/gateway admission accepts invalid transactions or rejects valid transactions before sequencing.** [6](#0-5) 

---

### Likelihood Explanation

The EIP-1559 mechanism adjusts `next_l2_gas_price` every block based on gas usage relative to `gas_target`. Any deviation from exactly-at-target usage (which is the normal operating condition) causes `next_l2_gas_price ≠ l2_gas_price`. The discrepancy grows monotonically during sustained congestion or sustained low usage. No special privileges or unusual conditions are required — any user submitting a transaction triggers the path. The TODO comment in the production code confirms the developers are aware the wrong field is being read.

---

### Recommendation

1. Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (either by adding it to `BlockInfo` or via a dedicated method on the trait).
2. In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, read `block_header.next_l2_gas_price` and surface it.
3. Replace the `l2_gas_price` reference in `validate_resource_bounds` with `next_l2_gas_price`. [7](#0-6) 

---

### Proof of Concept

**Setup:** Assume the previous committed block had `l2_gas_price = 100 FRI` and was 75% full. The EIP-1559 formula produces `next_l2_gas_price = 103 FRI` (approximately `+1/gas_price_max_change_denominator` per block at 75% utilization).

**Attacker/user action:**
1. User submits an invoke transaction with `AllResourceBounds { l2_gas: { max_price_per_unit: 101 FRI, max_amount: X } }`.
2. Gateway calls `validate_resource_bounds`. It reads `previous_block_l2_gas_price = 100 FRI` (the stale `l2_gas_price`). Threshold = `100% × 100 = 100`. Since `101 ≥ 100`, the transaction **passes** gateway admission.
3. Transaction enters the mempool and is pulled by the batcher for the next block.
4. Batcher builds block context with `l2_gas_price = 103 FRI` (from `next_l2_gas_price`).
5. Blockifier `check_fee_bounds` checks `101 < 103` → `ResourceBoundsError::MaxGasPriceTooLow` → transaction is **rejected** during pre-validation.
6. The transaction was admitted to the mempool, consumed batcher resources, and was never included in a block.

**Inverse (valid transaction rejected):** After a period of low usage, `next_l2_gas_price = 97 FRI` while `l2_gas_price = 100 FRI`. A user submits with `max_price_per_unit = 98 FRI`. Gateway rejects it (`98 < 100`), but the transaction would have succeeded in execution at `97 FRI`. [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L227-240)
```rust
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-57)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L403-448)
```rust
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
```

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
