### Title
Gateway L2 Gas Price Admission Check Uses Stale Previous-Block Price Instead of EIP-1559-Computed Next-Block Price — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` and `run_validate_entry_point` both validate a transaction's `max_price_per_unit` against the **previous committed block's** (block N) L2 gas price. The transaction will actually execute in **block N+1**, whose L2 gas price is computed by the EIP-1559 formula and can differ from block N's price. The batcher builds block N+1 with the EIP-1559-computed price and the blockifier re-validates resource bounds against that price. This creates a systematic mismatch: the gateway accepts transactions the batcher will reject, and rejects transactions the batcher would accept.

---

### Finding Description

**Root cause — wrong price epoch used for admission:**

In `validate_resource_bounds`, the threshold is derived from the previous block's L2 gas price:

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

The threshold is then `min_gas_price_percentage% × block_N_l2_gas_price`. The transaction passes if `tx.max_price_per_unit ≥ threshold`. [2](#0-1) 

In `run_validate_entry_point`, the same stale block info is reused to build the `BlockContext` for blockifier pre-validation, with only the block number bumped:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

So the blockifier's `check_fee_bounds` inside the gateway also runs against block N's gas prices, not block N+1's. [4](#0-3) 

**The batcher uses the correct price:**

The batcher receives `propose_block_input.block_info` from the consensus orchestrator, which contains the EIP-1559-computed next-block gas price: [5](#0-4) 

The EIP-1559 formula can move the price up or down each block: [6](#0-5) 

With `gas_used = ¾ × max_block_size` and `gas_target = ½ × max_block_size`, the price increases by ~1.04% per block (30 Gwei → 30.3125 Gwei per the snapshot test). [7](#0-6) 

**The `GatewayFixedBlockSyncStateClient` is fixed at the block number captured at validator instantiation time and caches the result permanently via `OnceCell`:** [8](#0-7) [9](#0-8) 

---

### Impact Explanation

Two failure modes arise:

**Mode A — Gateway accepts, batcher rejects (invalid tx admitted):**
Block N is heavily used → block N+1's EIP-1559 price P′ > P. A transaction with `max_price_per_unit = P` passes the gateway threshold (`P ≥ 100% × P`) but fails the batcher's `check_fee_bounds` (`P < P′`), producing a `MaxGasPriceTooLow` error. The transaction occupies a mempool slot and a batcher execution slot before being discarded.

**Mode B — Gateway rejects, batcher would accept (valid tx rejected):**
Block N is lightly used → block N+1's EIP-1559 price P′ < P. A transaction with `max_price_per_unit` in `[P′, P)` is rejected at the gateway (`price < 100% × P`) even though the batcher would have accepted it.

Both modes match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The L2 gas price changes every block whenever gas usage deviates from the target. Under normal network load (gas usage ≠ gas target), the price drifts continuously. Any user who sets `max_price_per_unit` exactly at the current block's price — the natural choice when following the network's published price — will hit Mode A whenever the next block's price is higher. No special privileges or adversarial setup are required; ordinary transaction submission is sufficient.

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` with the EIP-1559-projected next-block price. The orchestrator already exposes `calculate_next_l2_gas_price_for_fin` / `calculate_next_base_gas_price`. The gateway should call this with the previous block's gas usage to derive the expected next-block price and use that as the admission threshold. The same projected price should be used when constructing the `BlockContext` in `run_validate_entry_point`, so both gateway checks are consistent with what the batcher will enforce. [10](#0-9) 

---

### Proof of Concept

```
Setup:
  Block N: l2_gas_price = 30_000_000_000 fri (30 Gwei)
           gas_used     = ¾ × max_block_size  (high congestion)
           gas_target   = ½ × max_block_size

EIP-1559 projection (from snapshot test):
  Block N+1 l2_gas_price = 30_312_500_000 fri (~1.04% higher)

User submits Invoke V3 with:
  l2_gas.max_price_per_unit = 30_000_000_000  (exactly block N's price)

Gateway validate_resource_bounds:
  threshold = 100% × 30_000_000_000 = 30_000_000_000
  30_000_000_000 >= 30_000_000_000  → PASS ✓
  Transaction admitted to mempool.

Gateway run_validate_entry_point (blockifier with block N prices):
  check_fee_bounds: 30_000_000_000 >= 30_000_000_000 → PASS ✓

Batcher builds block N+1 (actual EIP-1559 price = 30_312_500_000):
  check_fee_bounds: 30_000_000_000 < 30_312_500_000
  → Err(MaxGasPriceTooLow { resource: L2Gas,
        max_gas_price: 30_000_000_000,
        actual_gas_price: 30_312_500_000 })
  Transaction rejected during block building. ✗

Inverse (Mode B):
  Block N lightly used → block N+1 price = 29_687_500_000
  User submits with max_price_per_unit = 29_800_000_000
  Gateway threshold = 30_000_000_000; 29_800_000_000 < 30_000_000_000 → REJECTED ✗
  Batcher would have accepted: 29_800_000_000 >= 29_687_500_000 ✓
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-372)
```rust
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-458)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
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
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/test.rs (L22-27)
```rust
#[rstest]
#[case::high_congestion(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 3 / 4),
    VERSIONED_CONSTANTS.max_block_size / 2,
    GasPrice(30312500000),
)]
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L19-27)
```rust
pub struct GatewayFixedBlockSyncStateClient {
    state_sync_client: SharedStateSyncClient,
    block_number: BlockNumber,
    block_info_cache: OnceCell<BlockInfo>,
}

impl GatewayFixedBlockSyncStateClient {
    pub fn new(state_sync_client: SharedStateSyncClient, block_number: BlockNumber) -> Self {
        Self { state_sync_client, block_number, block_info_cache: OnceCell::new() }
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L61-67)
```rust
impl GatewayFixedBlockStateReader for GatewayFixedBlockSyncStateClient {
    async fn get_block_info(&self) -> StarknetResult<BlockInfo> {
        self.block_info_cache
            .get_or_try_init(|| self.get_block_info_from_sync_client())
            .await
            .cloned()
    }
```
