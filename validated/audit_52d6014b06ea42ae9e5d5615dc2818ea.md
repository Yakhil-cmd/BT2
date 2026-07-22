### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Wrong Admission Decisions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **previous block's `l2_gas_price`** (the price that was used during block N's execution). The correct reference is `next_l2_gas_price` — the EIP-1559-adjusted price stored in the block header that will be enforced in block N+1. The code even carries a self-documenting TODO acknowledging this: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Finding Description

The gateway stateful validator reads the L2 gas price for its admission threshold from `BlockInfo.gas_prices.strk_gas_prices.l2_gas_price`:

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

This `BlockInfo` is constructed by `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, which populates `gas_prices` exclusively from `block_header.l2_gas_price` — the price that was used **inside** block N. It never reads `block_header.next_l2_gas_price`. [2](#0-1) 

The block header stores both fields distinctly:

```rust
pub struct BlockHeaderWithoutHash {
    pub l2_gas_price: GasPricePerToken,      // price used in block N
    pub next_l2_gas_price: GasPrice,          // EIP-1559 price for block N+1
    ...
}
``` [3](#0-2) 

`next_l2_gas_price` is computed by `calculate_next_l2_gas_price_for_fin` at the end of block N and stored in the block header. It is the price that the blockifier's `check_fee_bounds` will enforce when executing transactions in block N+1. [4](#0-3) 

The blockifier's `check_fee_bounds` enforces the **actual block context gas price** (which is `next_l2_gas_price` from block N, now the current block's price): [5](#0-4) 

The two prices diverge whenever a block is not at the gas target. The EIP-1559 mechanism adjusts the price up or down by up to `1/gas_price_max_change_denominator` per block. [6](#0-5) 

---

### Impact Explanation

**Case 1 — Block N over-utilized (`next_l2_gas_price > l2_gas_price`):**

The gateway threshold is `l2_gas_price * min_gas_price_percentage / 100`. A transaction with `max_price_per_unit` in the range `[l2_gas_price * threshold%, next_l2_gas_price)` passes the gateway check but will fail `check_fee_bounds` in the blockifier when the batcher attempts to execute it in block N+1. These transactions are admitted to the mempool, consume mempool slots, and waste batcher execution resources before being rejected.

**Case 2 — Block N under-utilized (`next_l2_gas_price < l2_gas_price`):**

The gateway threshold is higher than the actual next-block price. A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price * threshold%)` is rejected by the gateway even though it would pass `check_fee_bounds` in block N+1. Valid transactions are incorrectly rejected at the admission layer.

Both cases match: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

This triggers on every block where gas usage deviates from the gas target — which is the normal operating condition. The EIP-1559 price adjustment is continuous and automatic. Any user whose `max_price_per_unit` falls between `l2_gas_price` and `next_l2_gas_price` (in either direction) is affected. No special privileges are required; any unprivileged user submitting a standard V3 `AllResources` transaction can trigger either case.

---

### Recommendation

`GatewayFixedBlockStateReader` should expose `next_l2_gas_price` from the block header. `validate_resource_bounds` should use it instead of `l2_gas_price`:

```rust
// In GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client:
// Expose next_l2_gas_price separately, or add a dedicated method.

// In validate_resource_bounds:
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method reading block_header.next_l2_gas_price
    .await?;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_block_l2_gas_price,
)?;
```

This resolves the TODO comment and aligns the gateway admission check with the price that the blockifier will actually enforce.

---

### Proof of Concept

1. Observe block N with `l2_gas_price = 1000` and `next_l2_gas_price = 1100` (block was over-utilized, price rose 10%).
2. Submit an `InvokeV3` transaction with `AllResources` bounds where `l2_gas.max_price_per_unit = 1050`.
3. Gateway `validate_resource_bounds` computes threshold as `1000 * 100% = 1000`. Since `1050 >= 1000`, the transaction passes and is admitted to the mempool.
4. When the batcher executes the transaction in block N+1 (which uses `l2_gas_price = 1100`), `check_fee_bounds` finds `max_price_per_unit (1050) < actual_gas_price (1100)` and rejects the transaction with `MaxGasPriceTooLow`.
5. The transaction consumed a mempool slot and a batcher execution attempt despite being invalid for the target block. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-236)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-376)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
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

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```
