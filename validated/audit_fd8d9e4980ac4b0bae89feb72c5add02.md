### Title
Gateway Stateful Validator Rejects Valid V3 Transactions Using Stale Previous-Block L2 Gas Price as Mandatory Minimum — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`validate_tx_l2_gas_price_within_threshold` computes its rejection threshold from the **previous** block's L2 gas price, but the transaction will execute in the **next** block. When the L2 gas price decreases between blocks, the gateway rejects transactions whose `max_price_per_unit` is above the next block's actual price but below the stale previous-block price — causing valid transactions to be incorrectly denied admission. The code itself acknowledges the wrong reference with a `TODO` comment.

---

### Finding Description

In `validate_resource_bounds`, the gateway reads `previous_block_l2_gas_price` from `get_block_info()` and passes it to `validate_tx_l2_gas_price_within_threshold`: [1](#0-0) 

That function computes:

```
threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price
```

and rejects any V3 (`AllResources`) transaction whose `l2_gas.max_price_per_unit < threshold`: [2](#0-1) 

The default `min_gas_price_percentage` is **100**, so the threshold equals the previous block's L2 gas price exactly: [3](#0-2) 

However, the transaction will be executed in the **next** block, whose gas price may be lower. The code itself acknowledges this with a `TODO` at line 229: [4](#0-3) 

Meanwhile, `run_validate_entry_point` correctly increments the block number to simulate the next block: [5](#0-4) 

This creates a split: the gas-price admission check uses the **previous** block's price, but the blockifier validation and eventual execution use the **next** block's price. The two checks are inconsistent.

**Analog to the external bug:** Just as `_maxIncrease` was used as a mandatory growth factor — pulling coverage funds even when there was no actual loss — `previous_block_l2_gas_price` is used as a mandatory minimum, rejecting transactions even when they would be valid for the next block's actual price. In both cases a "reference bound" is misapplied as a hard floor, triggering the guard in scenarios where the underlying invariant is not actually violated.

---

### Impact Explanation

A user submitting a V3 (`AllResources`) transaction with `l2_gas.max_price_per_unit` set to a value **between** the next block's actual L2 gas price and the previous block's L2 gas price will receive a `GAS_PRICE_TOO_LOW` rejection at the gateway, even though the transaction would be perfectly valid for execution in the next block. This is a gateway admission error that incorrectly denies valid transactions.

**Matching impact:** High — Mempool/gateway/RPC admission rejects valid transactions before sequencing.

---

### Likelihood Explanation

The L2 gas price in Starknet is updated each block based on network demand. During any period of decreasing network activity the L2 gas price falls. Any user who sets `max_price_per_unit` to match the current (next) block's expected price rather than the previous block's price will be affected. The trigger is fully unprivileged — any user can submit such a transaction. The `TODO` comment confirms the developers already know the reference is wrong.

---

### Recommendation

Replace `previous_block_l2_gas_price` with the next block's L2 gas price as the reference for the threshold check. The `TODO` at line 229 already identifies the fix:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_block_info()   // or derive from block header
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_block_l2_gas_price,
)?;
```

This ensures the admission check and the execution context use the same gas price reference.

---

### Proof of Concept

1. Previous block L2 gas price: **100 units**
2. Next block L2 gas price: **80 units** (decreasing due to lower network activity)
3. User submits a V3 transaction with `l2_gas.max_price_per_unit = 90`
4. Gateway computes `threshold = 100 * 100 / 100 = 100`
5. Gateway rejects the transaction: `90 < 100` → `GAS_PRICE_TOO_LOW`
6. The transaction would be valid for execution: `90 > 80` (next block's price)

The transaction is incorrectly rejected at the gateway admission stage despite being economically valid for the next block.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-325)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L366-383)
```rust
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
