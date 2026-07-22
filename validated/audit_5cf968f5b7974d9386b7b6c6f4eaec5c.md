### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price` - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds()` checks the transaction's offered L2 gas price against the **previous block's `l2_gas_price`** (the price that was used *in* that block), but the next block will actually charge the **`next_l2_gas_price`** (computed via EIP-1559 from the previous block's gas consumption). This mismatch causes the gateway to admit transactions that blockifier will reject, and to reject transactions that blockifier would accept.

### Finding Description

In `validate_resource_bounds`, the gateway reads the threshold price from `get_block_info()`:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client()` constructs `BlockInfo` by mapping `block_header.l2_gas_price.price_in_fri` into `strk_gas_prices.l2_gas_price`:

```rust
strk_gas_prices: GasPriceVector {
    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

However, the block header also carries a distinct `next_l2_gas_price` field — the EIP-1559-adjusted price that will be used in the **next** block: [3](#0-2) 

`get_block_info_from_sync_client()` never reads `block_header.next_l2_gas_price`, so it is silently dropped. The `BlockInfo` struct returned to the validator only contains the stale `l2_gas_price`.

The threshold comparison in `validate_tx_l2_gas_price_within_threshold` then computes:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...GAS_PRICE_TOO_LOW...) }
``` [4](#0-3) 

This threshold is derived from the wrong price. The correct reference is `next_l2_gas_price`, which is what the sequencer will actually set as the current block's L2 gas price when building the next block.

The TODO comment in the source code explicitly acknowledges this: `// TODO(Arni): getnext_l2_gas_price from the block header.`

### Impact Explanation

The EIP-1559 formula (`calculate_next_base_gas_price`) can move the price by up to `price / gas_price_max_change_denominator` per block in either direction: [5](#0-4) 

**Case 1 — congested previous block (`next_l2_gas_price > l2_gas_price`):**
The gateway threshold is too low. A transaction with `max_price_per_unit` in the range `[threshold_from_l2_gas_price, threshold_from_next_l2_gas_price)` passes gateway admission and enters the mempool, but `AccountTransaction::check_fee_bounds` in the blockifier — which uses the actual current block's gas price (equal to `next_l2_gas_price`) — will reject it with `MaxGasPriceTooLow`. The gateway has admitted an invalid transaction.

**Case 2 — uncongested previous block (`next_l2_gas_price < l2_gas_price`):**
The gateway threshold is too high. A transaction with `max_price_per_unit` in the range `[threshold_from_next_l2_gas_price, threshold_from_l2_gas_price)` is rejected at the gateway with `GAS_PRICE_TOO_LOW`, even though blockifier would accept it. The gateway has rejected a valid transaction.

Both cases match: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

This triggers on every block where the previous block's gas consumption differs from the gas target (i.e., almost every block in practice). The magnitude of the discrepancy scales with how far gas usage deviates from the target. Any user submitting a V3 (`AllResources`) transaction with an L2 gas price near the threshold can trigger either case without any special privileges.

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client()`, expose `block_header.next_l2_gas_price` through the returned structure (or add a dedicated accessor to `GatewayFixedBlockStateReader`). Then in `validate_resource_bounds`, use `next_l2_gas_price` as the reference price instead of `l2_gas_price`. This is already acknowledged by the TODO comment at line 229.

### Proof of Concept

1. Observe that `StorageBlockHeader` / `BlockHeaderWithoutHash` carries both `l2_gas_price` and `next_l2_gas_price`.
2. Observe that `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client()` maps only `l2_gas_price` into `BlockInfo`, discarding `next_l2_gas_price`.
3. Observe that `validate_resource_bounds` reads `block_info.gas_prices.strk_gas_prices.l2_gas_price` and labels it `previous_block_l2_gas_price`, with the TODO comment confirming the correct field is `next_l2_gas_price`.
4. Construct a scenario where the previous block consumed more gas than the target: `next_l2_gas_price = l2_gas_price * (1 + delta/denominator)`. Submit a transaction with `max_price_per_unit = min_gas_price_percentage% * l2_gas_price`. It passes the gateway check (threshold = `min_gas_price_percentage% * l2_gas_price`) but fails `check_fee_bounds` in blockifier (threshold = `min_gas_price_percentage% * next_l2_gas_price > max_price_per_unit`).

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-383)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L124-129)
```rust
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```
