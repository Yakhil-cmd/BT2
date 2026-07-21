### Title
Gateway L2 Gas Price Validation Uses Stale Anchor (`l2_gas_price` of Previous Block Instead of `next_l2_gas_price`) — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful `validate_resource_bounds` check compares a transaction's `max_price_per_unit` against the **L2 gas price of the previous block** (`strk_gas_prices.l2_gas_price`). However, the actual block being built will execute transactions at the **next block's L2 gas price** (`next_l2_gas_price` stored in the previous block header). These two values diverge every block via the EIP-1559 adjustment mechanism. The code itself contains a `TODO` acknowledging the wrong field is used. This causes the gateway to either reject valid transactions (when price is falling) or admit transactions that will fail blockifier pre-validation (when price is rising).

---

### Finding Description

In `validate_resource_bounds`, the anchor used for the threshold check is obtained as:

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

The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri`:

```rust
strk_gas_prices: GasPriceVector {
    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

This is the price **used inside the previous block**, not `block_header.next_l2_gas_price`, which is the price **for the block currently being built**. The `next_l2_gas_price` field exists in `BlockHeaderWithoutHash` and is what the consensus orchestrator uses when constructing the new block's `BlockContext`. [3](#0-2) 

The threshold check then becomes:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
``` [4](#0-3) 

The `StatefulTransactionValidatorConfig` defaults `min_gas_price_percentage` to `100`, meaning the threshold equals the previous block's price exactly. [5](#0-4) 

---

### Impact Explanation

**Case 1 — Price rising (`next_l2_gas_price > l2_gas_price`):**
The gateway uses a lower anchor than the actual execution price. A transaction with `max_price_per_unit` in the range `[threshold * l2_gas_price, next_l2_gas_price)` passes gateway admission but will fail blockifier pre-validation (`check_fee_bounds`) when the batcher attempts to execute it, because the block context carries `next_l2_gas_price`. The transaction is admitted to the mempool but can never be included in a block — it occupies a mempool slot indefinitely.

**Case 2 — Price falling (`next_l2_gas_price < l2_gas_price`):**
The gateway uses a higher anchor than the actual execution price. A transaction with `max_price_per_unit` in the range `[threshold * next_l2_gas_price, threshold * l2_gas_price)` is **rejected** by the gateway even though it would satisfy the actual block's price requirement. Valid transactions are denied admission.

Both cases match the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The L2 gas price is updated every block by the EIP-1559 mechanism (adjustment denominator ~333, i.e., ~0.3% per block). The discrepancy is therefore **persistent and present on every block** where gas usage deviates from the target. Additionally, the `min_l2_gas_price_per_height` configuration can cause step-function jumps in `next_l2_gas_price` at specific heights, widening the gap significantly. [6](#0-5) 

No privileged access is required; any user submitting a V3 (`AllResources`) transaction during a period of price movement triggers the mismatch. Legacy `L1Gas` transactions are exempt from this check entirely, creating an asymmetry. [7](#0-6) 

---

### Recommendation

Replace the `l2_gas_price` field lookup with `next_l2_gas_price` from the block header. The `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` should read `block_header.next_l2_gas_price` and expose it (e.g., as a dedicated method or a separate field in `BlockInfo`), and `validate_resource_bounds` should use that value as the anchor. The existing `TODO` comment already identifies this exact fix. [8](#0-7) 

---

### Proof of Concept

1. Observe the previous block header: `l2_gas_price = P`, `next_l2_gas_price = P' = P * (1 + δ)` where `δ > 0` (price rising).
2. Submit a V3 `Invoke` transaction with `max_price_per_unit = P` (exactly equal to the previous block price, satisfying `min_gas_price_percentage = 100%`).
3. Gateway calls `validate_tx_l2_gas_price_within_threshold` with anchor `P`; check passes (`P >= 1.0 * P`).
4. Transaction is forwarded to the mempool and admitted.
5. Batcher builds the next block with `BlockContext` carrying `l2_gas_price = P'`.
6. Blockifier `check_fee_bounds` finds `max_price_per_unit (P) < block_l2_gas_price (P')` and raises `InsufficientResourceBounds`.
7. Transaction is never included in any block; it occupies a mempool slot until evicted.

For the rejection case, reverse step 1 to `P' < P` and submit with `max_price_per_unit = P'`; the gateway rejects it with `GAS_PRICE_TOO_LOW` even though the batcher would accept it.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L385-388)
```rust
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
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

**File:** crates/starknet_api/src/block.rs (L1-1)
```rust
#[cfg(test)]
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context_test.rs (L1735-1756)
```rust
    context.config.dynamic_config.min_l2_gas_price_per_height =
        vec![PricePerHeight { height: 250, price: CONFIG_MIN_PRICE_AT_250 }];

    // Sync succeeds at height 200, l2_gas_price is taken from synced next_l2_gas_price.
    assert!(context.try_sync(SYNC_HEIGHT).await);
    assert_eq!(context.l2_gas_price, GasPrice(SYNCED_NEXT_L2_GAS_PRICE));

    // First height initialization at 200: synced value is kept.
    context.set_height_and_round(SYNC_HEIGHT, ROUND_0).await.unwrap();
    assert_eq!(context.l2_gas_price, GasPrice(SYNCED_NEXT_L2_GAS_PRICE));

    // Move to height 250 where config min applies
    context.set_height_and_round(LATER_HEIGHT, ROUND_0).await.unwrap();
    // Bootstrap doesn't run (not first height anymore), price still 20g
    assert_eq!(context.l2_gas_price, GasPrice(SYNCED_NEXT_L2_GAS_PRICE));

    // Subsequent block should gradually increase toward CONFIG_MIN_PRICE_AT_250
    context.update_l2_gas_price(LATER_HEIGHT, GasAmount(1000));

    const MIN_GAS_PRICE_INCREASE_DENOMINATOR: u128 = 333;
    let expected_price =
        SYNCED_NEXT_L2_GAS_PRICE + (SYNCED_NEXT_L2_GAS_PRICE / MIN_GAS_PRICE_INCREASE_DENOMINATOR);
```
