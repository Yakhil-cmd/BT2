### Title
Gateway Resource Bounds Validation Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Systematic Admission/Rejection Mismatch — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check reads `block_header.l2_gas_price` (the price that was used in the already-committed block N) to validate incoming transactions. However, every transaction admitted through the gateway will execute in block N+1, whose L2 gas price is `block_header.next_l2_gas_price`. Because the EIP-1559 fee market adjusts the price every block, these two values routinely differ. The mismatch causes the gateway to admit transactions that will fail `check_fee_bounds` at execution time (when the price is rising) and to reject transactions that would have succeeded (when the price is falling). A developer TODO comment in the source code explicitly acknowledges the wrong field is being read.

---

### Finding Description

**Step 1 – Gateway reads the wrong field.**

`validate_resource_bounds` in `StatefulTransactionValidator` fetches the previous block's `BlockInfo` and extracts `strk_gas_prices.l2_gas_price`:

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

The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the price of the already-committed block — and never reads `block_header.next_l2_gas_price`: [2](#0-1) 

**Step 2 – The block header stores both values.**

`BlockHeaderWithoutHash` carries two distinct fields:
- `l2_gas_price: GasPricePerToken` — the price used inside block N
- `next_l2_gas_price: GasPrice` — the price that will be used in block N+1 [3](#0-2) 

The consensus context writes `self.l2_gas_price` (the EIP-1559-adjusted price for the upcoming block) into `next_l2_gas_price` when committing block N: [4](#0-3) 

**Step 3 – The blockifier entry-point validation also uses the stale price.**

`run_validate_entry_point` builds a `BlockContext` from the same stale `block_info` (only bumping the block number), so `check_fee_bounds` inside `perform_pre_validation_stage` also compares the transaction's `max_price_per_unit` against `P_N`, not `P_{N+1}`: [5](#0-4) 

**Step 4 – The batcher uses the correct price.**

When the batcher executes the transaction, the block context carries `l2_gas_price = P_{N+1}` (derived from `next_l2_gas_price` of block N). `check_fee_bounds` then enforces:

```
resource_bounds.max_price_per_unit >= P_{N+1}
``` [6](#0-5) 

**The invariant broken:** every transaction admitted by the gateway must satisfy `max_price_per_unit >= P_{N+1}`. The gateway enforces `max_price_per_unit >= P_N` instead.

---

### Impact Explanation

**When gas price is rising (`P_{N+1} > P_N`):**
A transaction with `P_N ≤ max_price_per_unit < P_{N+1}` passes both the gateway's `validate_resource_bounds` check and the blockifier's `check_fee_bounds` during `run_validate_entry_point`, is admitted to the mempool, and then fails `check_fee_bounds` at batcher execution time. The gateway has accepted a transaction that is invalid for the block it will execute in.

**When gas price is falling (`P_{N+1} < P_N`):**
A transaction with `P_{N+1} ≤ max_price_per_unit < P_N` is rejected by the gateway even though it would have passed `check_fee_bounds` at execution time. The gateway has rejected a valid transaction.

Both outcomes match the High impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The EIP-1559 `calculate_next_base_gas_price` adjusts `l2_gas_price` every block based on gas usage vs. the target. `P_{N+1} ≠ P_N` on every block where gas usage deviates from the target, which is the common case. The discrepancy is bounded per block by `gas_price_max_change_denominator`, but it is non-zero and cumulative. The `min_gas_price_percentage` configuration parameter provides partial mitigation only when set above 100 % and only for the rising-price direction; it does not fix the falling-price rejection case and does not fix the blockifier entry-point validation. [7](#0-6) 

---

### Recommendation

1. Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (or a dedicated method) so the gateway can read it from the block header.
2. In `validate_resource_bounds`, replace `block_info.gas_prices.strk_gas_prices.l2_gas_price` with `block_header.next_l2_gas_price`.
3. In `run_validate_entry_point`, override `block_info.gas_prices.strk_gas_prices.l2_gas_price` (and the corresponding wei price) with `next_l2_gas_price` before constructing the `BlockContext`, so the blockifier's `check_fee_bounds` at gateway time matches what the batcher will enforce.

The developer TODO comment already identifies the correct fix: [8](#0-7) 

---

### Proof of Concept

```
Block N committed:
  l2_gas_price        = 100 fri   (used inside block N)
  next_l2_gas_price   = 112 fri   (EIP-1559 increase; gas usage > target)

User submits Invoke V3 with:
  l2_gas.max_price_per_unit = 105 fri

Gateway validate_resource_bounds:
  threshold = min_gas_price_percentage% * 100 = 100  (at 100%)
  105 >= 100  →  PASS

Gateway run_validate_entry_point (blockifier check_fee_bounds):
  block_context.l2_gas_price = 100 fri  (stale)
  105 >= 100  →  PASS

Transaction admitted to mempool.

Batcher builds block N+1:
  block_context.l2_gas_price = 112 fri  (from next_l2_gas_price of block N)
  check_fee_bounds: 105 < 112  →  FAIL (InsufficientResourceBounds / MaxGasPriceTooLow)

Transaction fails at execution; fee may still be charged in revert flow.
```

The reverse (falling price) rejects a transaction with `max_price = 105` when `l2_gas_price = 112` and `next_l2_gas_price = 100`, even though the transaction would have executed successfully.

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

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
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
