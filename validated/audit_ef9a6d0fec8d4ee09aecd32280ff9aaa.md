### Title
Gateway Admission Uses Stale Previous-Block L2 Gas Price Instead of Next-Block Price, Causing Invalid Transactions to Be Admitted and Valid Transactions to Be Rejected - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` computes its admission threshold from the **previous (committed) block's** L2 gas price, while the blockifier's `check_fee_bounds` enforces the **current (next) block's** L2 gas price. Because the EIP-1559 mechanism adjusts the price every block, the two checks diverge: the gateway admits transactions whose `max_price_per_unit` is below the price that will actually be enforced at execution, and rejects transactions whose price is above the next-block price but below the previous-block price.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price from the latest committed block via `gateway_fixed_block_state_reader.get_block_info()` and names it `previous_block_l2_gas_price`. The code even carries an explicit developer TODO acknowledging the wrong value is being used:

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

The config description for `validate_resource_bounds` confirms the stale reference: *"ensures the max L2 gas price exceeds (a configurable percentage of) the **base gas price of the previous block**"*, with the default `min_gas_price_percentage` set to **100** (i.e., threshold = 100 % × P_prev). [2](#0-1) 

The threshold check in `validate_tx_l2_gas_price_within_threshold` rejects a transaction only when `tx_l2_gas_price < min_gas_price_percentage% × previous_block_l2_gas_price`. [3](#0-2) 

At blockifier execution time, `check_fee_bounds` inside `perform_pre_validation_stage` enforces the **current block's** gas price (`block_info.gas_prices`), which is the next block being built:

```rust
let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
    block_info.gas_prices.gas_price_vector(fee_type);
// ...
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

The EIP-1559 `calculate_next_base_gas_price` function adjusts the price every block based on gas usage. At 75 % block fullness the price rises ~1 % per block; at maximum fullness the increase is larger. [5](#0-4) 

The `GatewayFixedBlockSyncStateClient` caches the block info in a `OnceCell`, so the same stale price is reused for every transaction validated within the same gateway validator instance lifetime. [6](#0-5) 

---

### Impact Explanation

**Scenario A – Rising gas price (high congestion, price increases block-over-block):**

Let P_prev = previous block's L2 gas price, P_next = next block's L2 gas price (P_next > P_prev).

A transaction with `max_price_per_unit = P_prev`:
- Passes gateway: `P_prev >= 100% × P_prev` ✓
- Fails blockifier `check_fee_bounds`: `P_prev < P_next` ✗ → `MaxGasPriceTooLow`

The gateway admits a transaction that the blockifier will unconditionally reject. The transaction occupies a mempool slot and is handed to the batcher, which discards it during `perform_pre_validation_stage` without including it in any block.

**Scenario B – Falling gas price (low congestion, price decreases block-over-block):**

A transaction with `max_price_per_unit = P_next` (valid for the next block):
- Fails gateway: `P_next < 100% × P_prev` ✗ → `GAS_PRICE_TOO_LOW` rejection

The gateway rejects a transaction that the blockifier would have accepted.

Both scenarios are reachable by any unprivileged user submitting a standard `INVOKE` or `DECLARE` transaction with `AllResources` bounds during any period of non-zero gas-price movement, which is the normal operating state of the network.

---

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block. Any block with gas usage above the target (60 % of max block size) causes the price to rise. This is the expected steady-state under normal load. The default `min_gas_price_percentage = 100` means the threshold equals the previous block's price exactly, so even a 0.1 % price increase creates a gap. The trigger requires no special privileges: a user simply submits a transaction with `max_price_per_unit` equal to the current (previous-block) price, which is the natural value a wallet would compute from the latest block header.

---

### Recommendation

Replace `previous_block_l2_gas_price` with the **next block's** L2 gas price in `validate_resource_bounds`. The next-block price is already computed by `calculate_next_l2_gas_price_for_fin` / `calculate_next_base_gas_price` in the consensus orchestrator. The gateway should either:

1. Receive the pre-computed next-block L2 gas price from the batcher/consensus context and use it as the threshold reference, or
2. Compute it locally from the previous block's price and the previous block's gas usage (both available from the block header), matching the formula in `calculate_next_base_gas_price`.

The TODO comment at line 229 already identifies this fix: `// TODO(Arni): getnext_l2_gas_price from the block header.` [7](#0-6) 

---

### Proof of Concept

1. Observe the latest committed block N. Read its L2 gas price `P_N` from the block header. Observe that block N used more gas than the target (e.g., 75 % of max block size), so the EIP-1559 formula will produce `P_{N+1} > P_N` for block N+1.

2. Submit an `INVOKE` v3 transaction with `AllResources` bounds where `l2_gas.max_price_per_unit = P_N`.

3. The gateway calls `validate_resource_bounds`:
   - `previous_block_l2_gas_price = P_N`
   - `threshold = 100% × P_N = P_N`
   - `tx_l2_gas_price = P_N >= P_N` → **admitted**

4. The transaction enters the mempool and is handed to the batcher for block N+1.

5. The batcher builds block N+1 with `block_info.gas_prices.strk_gas_prices.l2_gas_price = P_{N+1} > P_N`.

6. `AccountTransaction::perform_pre_validation_stage` calls `check_fee_bounds`:
   - `resource_bounds.max_price_per_unit = P_N < P_{N+1} = actual_gas_price`
   - Returns `ResourceBoundsError::MaxGasPriceTooLow` → **rejected**

7. The transaction is not included in block N+1. The gateway admitted an invalid transaction.

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

**File:** crates/apollo_gateway_config/src/config.rs (L277-300)
```rust
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
