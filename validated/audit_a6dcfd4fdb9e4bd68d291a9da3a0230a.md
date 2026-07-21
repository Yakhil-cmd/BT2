### Title
Gateway L2 Gas Price Threshold Uses Wrong Block Field (`l2_gas_price` Instead of `next_l2_gas_price`), Admitting Transactions That Will Fail Execution or Rejecting Valid Ones - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks an incoming transaction's `max_price_per_unit` against the **current block's execution price** (`gas_prices.strk_gas_prices.l2_gas_price`) rather than the **EIP-1559-computed price for the next block** (`next_l2_gas_price`). Because every non-target-utilization block shifts the two values apart, the gateway systematically admits transactions whose gas price is too low for the block they will actually execute in, or rejects transactions that are perfectly valid for that block. The developers themselves flagged this with a `TODO` comment at the exact line.

### Finding Description

`validate_resource_bounds` in the stateful gateway validator reads the previous block's `BlockInfo` and extracts `strk_gas_prices.l2_gas_price` as the threshold reference:

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

The `StorageBlockHeader` carries two distinct price fields:

- `l2_gas_price`: the price **used to execute** transactions in that block.
- `next_l2_gas_price`: the EIP-1559-adjusted price **for the next block**, computed from `l2_gas_consumed` and `gas_target`. [2](#0-1) 

The `BlockInfo` struct returned by `get_block_info()` only exposes `gas_prices` (the execution price), not `next_l2_gas_price`. The TODO comment acknowledges the correct field is not yet being read.

The threshold function then computes:

```
threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price
``` [3](#0-2) 

With the default `min_gas_price_percentage = 100`, the threshold equals `l2_gas_price` exactly. But the transaction will execute in the **next** block at `next_l2_gas_price`, which diverges from `l2_gas_price` by up to `price / gas_price_max_change_denominator` per block under EIP-1559. [4](#0-3) 

**Over-utilized block scenario** (`next_l2_gas_price > l2_gas_price`):  
A transaction with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` passes the gateway check but will be rejected by blockifier's `check_fee_bounds` / `verify_can_pay_committed_bounds` at execution time with `MaxGasPriceTooLow`. The gateway has admitted an invalid transaction.

**Under-utilized block scenario** (`next_l2_gas_price < l2_gas_price`):  
A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price)` is rejected by the gateway even though it would succeed in the next block. The gateway has rejected a valid transaction. [5](#0-4) 

The analog to the external `highWaterMark` bug is exact: both use a stale/wrong baseline value as the checkpoint for an accounting/admission invariant. In Popcorn, `highWaterMark` was reset on every deposit instead of only on fee collection. Here, the price baseline is read from the wrong field of the block header, causing the admission check to operate on a value that does not represent the price the transaction will actually face.

### Impact Explanation

**High** — Mempool/gateway admission accepts invalid transactions (over-utilized blocks) or rejects valid transactions (under-utilized blocks) before sequencing. Admitted-but-invalid transactions consume mempool capacity and batcher execution resources before being reverted. Rejected-but-valid transactions degrade user experience and liveness. The discrepancy grows with sustained block utilization above or below the gas target.

### Likelihood Explanation

Any block whose gas consumption differs from `gas_target` produces a non-zero divergence between `l2_gas_price` and `next_l2_gas_price`. Under normal network load this occurs on virtually every block. No special attacker capability is required; the bug is triggered by ordinary transaction submission.

### Recommendation

Replace the `get_block_info()` call with a method that returns `next_l2_gas_price` from the block header, and use that value as the threshold reference:

```rust
let next_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method returning StorageBlockHeader::next_l2_gas_price
    .await?;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_l2_gas_price,
)?;
```

The `GatewayFixedBlockStateReader` trait should be extended to expose `next_l2_gas_price` directly from the stored block header, resolving the acknowledged TODO.

### Proof of Concept

1. Observe the previous block was fully utilized (gas_used ≈ 2 × gas_target).
2. Compute `next_l2_gas_price ≈ l2_gas_price * (1 + 1/denominator)` — e.g., 12.5% higher.
3. Submit an invoke transaction V3 with `l2_gas.max_price_per_unit = l2_gas_price` (exactly at the current block price).
4. Gateway calls `validate_tx_l2_gas_price_within_threshold` with `previous_block_l2_gas_price = l2_gas_price`; threshold = `l2_gas_price`; check passes.
5. Transaction enters mempool.
6. Batcher selects transaction for the next block; blockifier calls `check_fee_bounds` with the actual `next_l2_gas_price`; `max_price_per_unit < next_l2_gas_price`; transaction fails with `MaxGasPriceTooLow`.
7. Gateway has admitted a transaction that cannot execute — matching the "High: Mempool/gateway/RPC admission accepts invalid transactions" impact category. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L223-243)
```rust
    async fn validate_resource_bounds(
        &self,
        executable_tx: &ExecutableTransaction,
    ) -> StatefulTransactionValidatorResult<()> {
        // Skip this validation during the systems bootstrap phase.
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
        Ok(())
    }
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

**File:** crates/apollo_storage/src/header.rs (L84-89)
```rust
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-458)
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

**File:** crates/apollo_node/resources/config_schema.json (L3112-3126)
```json
  "gateway_config.static_config.stateful_tx_validator_config.min_gas_price_percentage": {
    "description": "Minimum gas price as percentage of threshold to accept transactions.",
    "privacy": "Public",
    "value": 100
  },
  "gateway_config.static_config.stateful_tx_validator_config.reject_future_declare_txs": {
    "description": "If true, rejects declare transactions with future nonces.",
    "privacy": "Public",
    "value": true
  },
  "gateway_config.static_config.stateful_tx_validator_config.validate_resource_bounds": {
    "description": "If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas price of the previous block.",
    "pointer_target": "validate_resource_bounds",
    "privacy": "Public"
  },
```
