### Title
Gateway Stateful Validator Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` for Resource Bounds Admission - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check compares a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price` (block N). The transaction will actually execute in the **next block** (N+1), whose L2 gas price is `next_l2_gas_price` — a distinct field in the block header computed by the EIP-1559 fee market. The code itself acknowledges this with a TODO comment. The mismatch causes the gateway to admit transactions that will fail at execution time (when `next_l2_gas_price > l2_gas_price`) and to reject transactions that would succeed (when `next_l2_gas_price < l2_gas_price`).

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` fetches the block info from `GatewayFixedBlockSyncStateClient` and reads `gas_prices.strk_gas_prices.l2_gas_price` — the price **of the latest committed block** (block N):

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates this field from `block_header.l2_gas_price.price_in_fri`:

```rust
strk_gas_prices: GasPriceVector {
    ...
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

`BlockHeaderWithoutHash` carries **two separate fields**: `l2_gas_price` (the price used in block N) and `next_l2_gas_price` (the EIP-1559-derived price for block N+1): [3](#0-2) 

The consensus orchestrator stores `context.l2_gas_price` (which equals `next_l2_gas_price` from block N) and passes it as `l2_gas_price_fri` in `ProposalInit` to the batcher for actual execution:

```rust
l2_gas_price_fri: args.l2_gas_price,   // = next_l2_gas_price from block N
``` [4](#0-3) 

The batcher then uses this value as the block context's L2 gas price when executing transactions. The blockifier's `check_fee_bounds` therefore enforces `tx.max_price_per_unit >= next_l2_gas_price`, while the gateway enforced `tx.max_price_per_unit >= l2_gas_price`. These two values diverge every block via the EIP-1559 adjustment in `calculate_next_base_gas_price`: [5](#0-4) 

The `next_l2_gas_price` is also written into the block header by `update_state_sync_with_new_block`:

```rust
next_l2_gas_price: self.l2_gas_price,
``` [6](#0-5) 

So the correct value is available in the block header but is never read by the gateway validator.

### Impact Explanation

**Direction 1 — Invalid transactions admitted (mempool pollution):** When a block is heavily used, `next_l2_gas_price > l2_gas_price`. Transactions with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` pass the gateway's threshold check but will be rejected by the blockifier's `check_fee_bounds` during actual block building. These transactions enter the mempool, consume resources, and are silently dropped at sequencing time.

**Direction 2 — Valid transactions rejected (denial of service):** When a block is lightly used, `next_l2_gas_price < l2_gas_price`. Transactions with `max_price_per_unit` in `[next_l2_gas_price, l2_gas_price)` are rejected by the gateway even though they would be accepted and executed correctly by the blockifier. Users whose wallets set `max_price_per_unit` to the correct next-block price are incorrectly turned away.

Both directions match the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The EIP-1559 fee market adjusts the L2 gas price every block based on gas consumption relative to `gas_target`. Any block that is not exactly at the target causes `next_l2_gas_price ≠ l2_gas_price`. This is the normal operating condition of the network, not an edge case. The discrepancy magnitude is bounded by `price / gas_price_max_change_denominator` per block, but it is always present under real load. No special privileges or unusual conditions are required — any user submitting a transaction triggers the path.

### Recommendation

In `validate_resource_bounds`, replace the read of `l2_gas_price` with `next_l2_gas_price` from the block header. The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` should expose `next_l2_gas_price` (already present in `BlockHeaderWithoutHash`) either as a separate field on `BlockInfo` or via a dedicated accessor on `GatewayFixedBlockStateReader`. The TODO comment at line 229 already identifies this fix.

### Proof of Concept

1. Block N is committed with `l2_gas_price = 10 Gwei` and `next_l2_gas_price = 11 Gwei` (block was full, EIP-1559 raised the price).
2. A user submits an invoke transaction with `l2_gas.max_price_per_unit = 10 Gwei`.
3. `validate_resource_bounds` computes threshold = `100% × 10 Gwei = 10 Gwei`; `10 >= 10` → **admitted to mempool**.
4. The batcher builds block N+1 with `l2_gas_price_fri = 11 Gwei` (from `context.l2_gas_price = next_l2_gas_price`).
5. Blockifier's `check_fee_bounds` checks `10 Gwei < 11 Gwei` → **transaction rejected at execution time**.
6. The transaction was admitted to the mempool, consumed gateway and mempool resources, and is silently dropped — the user receives no timely rejection and must resubmit with a higher price.

Reverse scenario (valid transaction rejected): Block N has `l2_gas_price = 10 Gwei`, `next_l2_gas_price = 9 Gwei` (block was empty). A user submits with `max_price_per_unit = 9 Gwei`. Gateway threshold = `10 Gwei`; `9 < 10` → **rejected**, even though the blockifier would accept it at `9 Gwei`.

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
```

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_consensus_orchestrator/src/build_proposal.rs (L177-177)
```rust
        l2_gas_price_fri: args.l2_gas_price,
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-139)
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
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L405-405)
```rust
            next_l2_gas_price: self.l2_gas_price,
```
