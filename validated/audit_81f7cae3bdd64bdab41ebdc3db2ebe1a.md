### Title
Gateway L2 Gas Price Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Wrong Admission Decisions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful `validate_resource_bounds` check compares a transaction's offered L2 gas price against the **previous block's `l2_gas_price`** (the price that was used in the already-committed block). However, the batcher executes the transaction against the **next block's L2 gas price** (`next_l2_gas_price` from the previous block header, computed via EIP-1559). These two values can diverge substantially. The gateway therefore uses the wrong price oracle — an exact structural analog to the WBTC/BTC depeg issue — causing it to admit transactions that will fail at execution (rising-price regime) or reject transactions that would succeed (falling-price regime).

### Finding Description

In `validate_resource_bounds` the gateway reads the previous block's `strk_gas_prices.l2_gas_price` and uses it as the reference for the admission threshold:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;                          // ← price used IN the previous block
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,            // ← wrong reference
)?;
``` [1](#0-0) 

The `GatewayFixedBlockSyncStateClient` builds `BlockInfo` from the block header but silently drops `block_header.next_l2_gas_price`:

```rust
gas_prices: GasPrices {
    strk_gas_prices: GasPriceVector {
        l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
        // next_l2_gas_price is never read here
        ...
    },
},
``` [2](#0-1) 

The `StorageBlockHeader` (and `BlockHeaderWithoutHash`) carries both fields as distinct values:

```rust
pub l2_gas_price: GasPricePerToken,   // price used in this block
pub next_l2_gas_price: GasPrice,      // EIP-1559 price for the NEXT block
``` [3](#0-2) 

The consensus orchestrator stores `self.l2_gas_price` (the EIP-1559-adjusted price) as `next_l2_gas_price` in the block header and then uses it as the actual gas price for the next block's `ProposalInit`:

```rust
next_l2_gas_price: self.l2_gas_price,   // written to header
``` [4](#0-3) 

The batcher then builds `BlockInfo` from `ProposalInit.l2_gas_price_fri`, which equals that `next_l2_gas_price`:

```rust
let l2_gas_price_fri = NonzeroGasPrice::new(init.l2_gas_price_fri)?;
``` [5](#0-4) 

The blockifier's `check_fee_bounds` then enforces `tx.max_price_per_unit >= actual_gas_price` using that batcher-supplied price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [6](#0-5) 

The EIP-1559 formula can move `next_l2_gas_price` materially away from `l2_gas_price` within a single block:

```rust
let price_change = (price_u256 * gas_delta) / denominator;
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [7](#0-6) 

### Impact Explanation

**Rising-price regime** (`next_l2_gas_price > l2_gas_price`, e.g. a full block): the gateway threshold is `min_gas_price_percentage% × l2_gas_price` (lower). A transaction with `max_price_per_unit` in the range `[threshold, next_l2_gas_price)` passes gateway admission but is rejected by the blockifier during batcher execution. The gateway admits transactions that are invalid for the next block.

**Falling-price regime** (`next_l2_gas_price < l2_gas_price`, e.g. an empty block): the gateway threshold is `min_gas_price_percentage% × l2_gas_price` (higher). A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, threshold)` is rejected by the gateway but would be accepted by the blockifier. The gateway rejects transactions that are valid for the next block.

Both outcomes match the **High** allowed impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The EIP-1559 price adjustment is continuous and automatic. Any block that deviates from the gas target (the common case) produces a `next_l2_gas_price ≠ l2_gas_price`. No special attacker capability is required; any user submitting a transaction near the price boundary triggers the mismatch. The TODO comment in the source confirms the developers are aware the wrong field is being read.

### Recommendation

Replace the `l2_gas_price` read with `next_l2_gas_price` from the block header. This requires:

1. Extending `GatewayFixedBlockStateReader::get_block_info` (or adding a new method) to expose `next_l2_gas_price` from `BlockHeaderWithoutHash`.
2. Updating `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` to read `block_header.next_l2_gas_price`.
3. Passing `next_l2_gas_price` to `validate_tx_l2_gas_price_within_threshold` instead of `strk_gas_prices.l2_gas_price`.

This mirrors the "double oracle" recommendation in the external report: use the price that will actually govern execution (`next_l2_gas_price`) rather than a stale proxy (`l2_gas_price`).

### Proof of Concept

1. Observe a block where `gas_used > gas_target` so that `next_l2_gas_price = P_next > P_prev = l2_gas_price`.
2. Submit an `InvokeV3` transaction with `l2_gas.max_price_per_unit = P_prev` (satisfies `>= threshold * P_prev` with any non-zero `min_gas_price_percentage`).
3. The gateway calls `validate_tx_l2_gas_price_within_threshold(P_prev, P_prev)` → passes.
4. The transaction enters the mempool.
5. The batcher builds the next block with `l2_gas_price = P_next`.
6. `check_fee_bounds` evaluates `P_prev < P_next` → `MaxGasPriceTooLow` → transaction is rejected at execution time.

The gateway has admitted a transaction that is invalid for the block it will be sequenced into, wasting mempool capacity and batcher resources. Conversely, submitting with `max_price_per_unit = P_next` in a falling-price regime (`P_next < threshold * P_prev`) causes the gateway to reject a transaction the batcher would have accepted.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-240)
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L404-406)
```rust
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
```

**File:** crates/apollo_consensus_orchestrator/src/utils.rs (L317-317)
```rust
    let l2_gas_price_fri = NonzeroGasPrice::new(init.l2_gas_price_fri)?;
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L126-129)
```rust
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```
