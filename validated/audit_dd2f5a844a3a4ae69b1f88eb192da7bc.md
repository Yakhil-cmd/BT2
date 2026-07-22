### Title
Gateway Stateful Validator Admits Transactions Using Stale Previous-Block L2 Gas Price, Causing Execution-Time Rejection — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks the transaction's `l2_gas.max_price_per_unit` against the **previous block's** L2 gas price, but the actual execution block uses the **next block's** L2 gas price computed via EIP-1559. Under high congestion the next-block price is strictly higher than the previous-block price, so transactions that pass every gateway check are admitted to the mempool and then rejected at execution time with `MaxGasPriceTooLow`. This is the sequencer-native analog of the Stargate bug: a fixed/stale amount is used for the admission decision while the actual value at processing time is larger.

---

### Finding Description

`validate_resource_bounds` reads the gas price from the **latest committed block** via `gateway_fixed_block_state_reader.get_block_info()`:

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

The threshold check passes when `tx.l2_gas_price >= (min_gas_price_percentage / 100) * prev_block_price`. [2](#0-1) 

`run_validate_entry_point` builds the blockifier `BlockContext` from the **same** stale `get_block_info()` call (only incrementing `block_number`, not the gas prices), so the blockifier's `check_fee_bounds` at gateway time also uses `prev_block_l2_gas_price`:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
// gas_prices are NOT updated — still previous block's prices
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

At actual execution time the batcher uses the **next** block's L2 gas price, computed by `calculate_next_base_gas_price` (EIP-1559). Under high congestion (`gas_used > gas_target`) this price is strictly greater than the previous block's price:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [4](#0-3) 

The blockifier's `check_fee_bounds` at execution time then rejects the transaction:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

**Concrete invariant broken:** A transaction with `prev_block_l2_gas_price ≤ tx.l2_gas_price < next_block_l2_gas_price` passes all three gateway checks (threshold check, blockifier pre-validation, `__validate__` entry point) but fails `check_fee_bounds` at sequencing time. The gateway's admission decision is therefore wrong.

---

### Impact Explanation

Every admitted transaction that carries `l2_gas.max_price_per_unit` in the range `[prev_block_price, next_block_price)` will be rejected by the blockifier at sequencing time with a pre-validation error. This means the gateway **accepts invalid transactions** — transactions that cannot be included in the next block — polluting the mempool and wasting sequencer resources. The TODO comment in the source confirms the code author is aware the wrong price is being used.

Impact: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

This condition is triggered whenever the network is under above-target load, which is a routine operating state. The EIP-1559 formula can raise the price by up to `price * gas_delta / (gas_target * denominator)` per block. At 75% block fullness (a common congestion level) the price rises by ~2% per block. Any user who submits a transaction with `max_price_per_unit` equal to the current block's price will be admitted by the gateway but rejected at sequencing. No special privileges are required; any unprivileged user can trigger this by submitting a V3 `AllResources` transaction with `l2_gas.max_price_per_unit = prev_block_l2_gas_price`.

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` with the **next block's** L2 gas price in `validate_resource_bounds`. The next-block price is already computed by `calculate_next_l2_gas_price_for_fin` / `calculate_next_base_gas_price` and is stored in `block_header_without_hash.next_l2_gas_price`. The gateway should read `next_l2_gas_price` from the latest committed block header (which records the price for the *following* block) rather than `gas_prices.strk_gas_prices.l2_gas_price` (which is the price of the *current* block). This is exactly what the TODO comment already requests:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [6](#0-5) 

The same fix must be applied to the `BlockContext` constructed inside `run_validate_entry_point` so that the blockifier's `check_fee_bounds` at gateway time uses the same price that will be used at execution time.

---

### Proof of Concept

1. Observe the current block's L2 gas price `P` from the latest committed block header.
2. Submit a V3 `AllResources` invoke transaction with `l2_gas.max_price_per_unit = P` and `min_gas_price_percentage = 100` (default).
3. Gateway threshold check: `P >= 1.0 * P` → **passes**.
4. Gateway blockifier `check_fee_bounds`: `P >= P` (previous block price) → **passes**.
5. `__validate__` entry point: **passes** (no gas price check there).
6. Transaction is admitted to the mempool.
7. At sequencing time the batcher builds the next block. Under any above-target congestion `calculate_next_base_gas_price(P, gas_used > gas_target, ...)` returns `P' > P`.
8. Blockifier `check_fee_bounds` at execution: `P < P'` → **`MaxGasPriceTooLow` — transaction rejected**.

The transaction was admitted by the gateway but cannot be sequenced, confirming the invariant violation.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L128-139)
```rust
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
