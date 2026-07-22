### Title
Gateway Stateful Validator Uses Previous Block's L2 Gas Price Instead of Next Block's Price for Resource Bounds Admission — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` compares a transaction's offered L2 gas price against the **previous block's** L2 gas price, but the transaction will be executed in the **next block**, which carries a different L2 gas price. This is a direct analog of the cross-chain timestamp mismatch: a reference value from one context (previous block) is used to gate admission for a different context (next block), causing valid transactions to be rejected and invalid transactions to be admitted.

### Finding Description

In `validate_resource_bounds`, the gateway reads `previous_block_l2_gas_price` from `gateway_fixed_block_state_reader.get_block_info()`:

```rust
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

The threshold is then computed as a fraction of that previous-block price:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(StarknetError { code: "GAS_PRICE_TOO_LOW" ... });
}
``` [2](#0-1) 

However, when the same transaction reaches `run_validate_entry_point`, the block context is built for the **next** block:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
``` [3](#0-2) 

The blockifier's `check_fee_bounds` then validates the transaction's `max_price_per_unit` against the **next block's** actual gas price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

The block header already carries the correct reference value — `next_l2_gas_price` — but it is not used. The code even contains an explicit TODO acknowledging the bug:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [5](#0-4) 

The `next_l2_gas_price` field is present in `StorageBlockHeader`: [6](#0-5) 

### Impact Explanation

Two distinct failure modes arise from the context mismatch:

**False rejection (valid transaction rejected at gateway):** When the previous block's L2 gas price is high, the admission threshold is high. A transaction whose offered price satisfies the next block's actual price (which may have dropped) is rejected with `GAS_PRICE_TOO_LOW` even though the blockifier would accept it. This is a **High** impact: valid transactions are denied sequencing.

**False acceptance (invalid transaction admitted to mempool):** When the previous block's L2 gas price is low, the admission threshold is low. A transaction whose offered price is below the next block's actual price passes the gateway check, enters the mempool, and then fails `check_fee_bounds` during blockifier pre-validation. This is a **High** impact: the gateway admits transactions that will be rejected by the sequencer, wasting mempool and sequencer resources and producing misleading admission signals to users.

### Likelihood Explanation

The L2 gas price changes every block via the `next_l2_gas_price` mechanism. Any block-to-block price movement — upward or downward — creates a window where the gateway's admission decision diverges from the blockifier's execution decision. This is a normal operating condition, not an edge case.

### Recommendation

Replace `previous_block_l2_gas_price` (the current block's `l2_gas_price`) with `next_l2_gas_price` from the same block header in `validate_resource_bounds`. The `StorageBlockHeader` already exposes this field. This aligns the gateway's admission reference with the price that the blockifier will enforce during execution.

### Proof of Concept

**Scenario A — valid transaction rejected:**
1. Previous (current) block: `l2_gas_price = 1000 FRI`, `next_l2_gas_price = 500 FRI`.
2. User submits transaction with `l2_gas.max_price_per_unit = 600 FRI`.
3. Gateway threshold (90%): `0.9 × 1000 = 900`. Gateway rejects: `600 < 900` → `GAS_PRICE_TOO_LOW`.
4. Blockifier would accept: `600 ≥ 500` ✓. Transaction is incorrectly denied.

**Scenario B — invalid transaction admitted:**
1. Previous (current) block: `l2_gas_price = 100 FRI`, `next_l2_gas_price = 1000 FRI`.
2. User submits transaction with `l2_gas.max_price_per_unit = 150 FRI`.
3. Gateway threshold (90%): `0.9 × 100 = 90`. Gateway accepts: `150 ≥ 90` ✓.
4. Blockifier rejects: `150 < 1000` → `MaxGasPriceTooLow`. Transaction admitted to mempool but fails execution.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-241)
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
        }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-324)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
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

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```
