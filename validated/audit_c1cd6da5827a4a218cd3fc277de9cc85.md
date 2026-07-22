### Title
Gateway Stateful Validator Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` for Fee Admission Threshold — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` computes the admission threshold from the **current** block's `l2_gas_price` field, but transactions submitted to the gateway will be included in the **next** block, whose L2 gas price is `next_l2_gas_price`. The code itself carries a `TODO` acknowledging this. When the EIP-1559-style fee market moves the price between blocks, the wrong reference value causes the gateway to either accept transactions that will fail blockifier fee-bound checks, or reject transactions that are perfectly valid for the next block.

---

### Finding Description

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

- `l2_gas_price` — the price that was used **in the current (latest committed) block**
- `next_l2_gas_price` — the price that **will be used in the next block** (computed by the EIP-1559 algorithm at the end of the current block) [1](#0-0) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` converts the block header into a `BlockInfo` struct. It maps `block_header.l2_gas_price` into `BlockInfo.gas_prices.strk_gas_prices.l2_gas_price`, and **silently drops** `block_header.next_l2_gas_price`: [2](#0-1) 

`StatefulTransactionValidator::validate_resource_bounds` then reads back `strk_gas_prices.l2_gas_price` as the reference price for the admission threshold. The inline `TODO` comment explicitly acknowledges the wrong field is being used: [3](#0-2) 

The threshold is then computed as:

```
threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price
``` [4](#0-3) 

Because `l2_gas_price ≠ next_l2_gas_price` whenever the fee market adjusts the price, the threshold is wrong in both directions.

---

### Impact Explanation

**Case 1 — Gas price rising (next > current):**
The gateway threshold is computed from the lower `l2_gas_price`. A transaction whose `max_price_per_unit` satisfies `threshold(l2_gas_price) ≤ price < threshold(next_l2_gas_price)` passes gateway admission and enters the mempool, but will fail the blockifier's `check_fee_bounds` / `verify_can_pay_committed_bounds` during block execution. The gateway has admitted an invalid transaction.

**Case 2 — Gas price falling (next < current):**
The gateway threshold is computed from the higher `l2_gas_price`. A transaction whose `max_price_per_unit` satisfies `threshold(next_l2_gas_price) ≤ price < threshold(l2_gas_price)` is rejected at the gateway even though it would be perfectly valid for the next block. Valid transactions are incorrectly excluded from sequencing.

Both cases match the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The EIP-1559 L2 gas price algorithm (`calculate_next_base_gas_price`) adjusts the price every block based on gas consumption relative to the target. On a live network with variable load, `l2_gas_price ≠ next_l2_gas_price` is the normal case, not the exception. Any user submitting a transaction during a period of price movement (rising or falling) can trigger either admission path. No privileged access is required. [5](#0-4) 

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, expose `block_header.next_l2_gas_price` so it is available to the validator. Then in `StatefulTransactionValidator::validate_resource_bounds`, replace the read of `gas_prices.strk_gas_prices.l2_gas_price` with the `next_l2_gas_price` value from the block header. This resolves the `TODO` comment and aligns the admission threshold with the price that will actually govern the block the transaction is destined for. [6](#0-5) 

---

### Proof of Concept

1. Observe the current block's `l2_gas_price` = P and `next_l2_gas_price` = P′ where P′ > P (rising market, e.g., block was above gas target).
2. Set `min_gas_price_percentage` = 100 (default-like). Threshold from current code = P; correct threshold = P′.
3. Submit an invoke transaction with `max_price_per_unit` = P (satisfies current code's threshold, fails correct threshold).
4. Gateway calls `validate_resource_bounds` → passes (P ≥ P).
5. Transaction enters mempool and is selected for the next block.
6. Blockifier's `check_fee_bounds` uses the next block's actual gas price P′ → `max_price_per_unit` P < P′ → `InsufficientResourceBounds` error.
7. Transaction reverts or is dropped, but it was admitted through the gateway — breaking the admission invariant. [7](#0-6) [8](#0-7)

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
