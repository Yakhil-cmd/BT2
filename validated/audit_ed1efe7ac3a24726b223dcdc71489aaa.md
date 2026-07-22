### Title
Gateway Stateful Validator Uses Stale `l2_gas_price` Snapshot Instead of `next_l2_gas_price` for Admission Control — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `validate_resource_bounds` reads the **previous block's `l2_gas_price`** as the admission threshold, while the batcher executes transactions against the EIP-1559-computed **`next_l2_gas_price`**. Because these two values diverge every block, the gateway systematically accepts transactions that will fail at blockifier execution (price rising) and rejects transactions that would succeed (price falling). The code itself acknowledges the bug with an inline TODO.

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the threshold is obtained as:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates this from `block_header.l2_gas_price.price_in_fri` — the price **used in** the previous block, not the price **computed for** the next block: [2](#0-1) 

The `StorageBlockHeader` carries a separate `next_l2_gas_price` field (the EIP-1559 output for the upcoming block): [3](#0-2) 

The batcher, however, passes `next_l2_gas_price` as the L2 gas price for the new block when it calls `update_gas_price` on the mempool and when it builds the `BlockContext` for execution: [4](#0-3) 

The same stale `block_info` (previous block's prices, block number bumped by one) is also used inside `run_validate_entry_point` for the blockifier pre-validation: [5](#0-4) 

So both the explicit threshold check and the blockifier `check_fee_bounds` inside the gateway use the **old** price, while the batcher uses the **new** price. The gap between the two is exactly one EIP-1559 step.

The threshold comparison that enforces the check: [6](#0-5) 

Note also that `ValidResourceBounds::L1Gas(_)` transactions are **entirely exempt** from this check (`// No validation required for legacy transactions.`), so the stale-snapshot path is only exercised for `AllResources` (V3) transactions.

### Impact Explanation

**Case A — price rising (`next_l2_gas_price > l2_gas_price`):**  
A transaction with `max_l2_gas_price = l2_gas_price` passes the gateway threshold (`>= 100 % × l2_gas_price`) and passes the gateway's own blockifier pre-validation (which also uses the old price). It is admitted to the mempool. When the batcher executes it, `check_fee_bounds` compares against `next_l2_gas_price` and raises `MaxGasPriceTooLow`. The gateway admitted an invalid transaction.

**Case B — price falling (`next_l2_gas_price < l2_gas_price`):**  
A transaction with `max_l2_gas_price = next_l2_gas_price` would succeed at batcher execution, but the gateway rejects it with `GAS_PRICE_TOO_LOW` because `next_l2_gas_price < 100 % × l2_gas_price`. A valid transaction is rejected before sequencing.

Both outcomes match the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The L2 gas price changes every block whenever block gas usage differs from the EIP-1559 target. On a live network this is the common case. No special privileges are required; any user submitting a V3 (`AllResources`) transaction with `max_l2_gas_price` in the gap between the two prices triggers the discrepancy. The `validate_resource_bounds` flag defaults to `true` in `StatefulTransactionValidatorConfig`: [7](#0-6) 

### Recommendation

1. Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (currently only `l2_gas_price` is surfaced via `BlockInfo`).
2. In `validate_resource_bounds`, replace the read of `gas_prices.strk_gas_prices.l2_gas_price` with the `next_l2_gas_price` from the block header, resolving the inline TODO.
3. In `run_validate_entry_point`, populate the `block_info` passed to `BlockContext` with `next_l2_gas_price` as the L2 gas price so that gateway blockifier pre-validation uses the same price the batcher will use.

### Proof of Concept

```
Previous block: l2_gas_price = 100 fri, gas_used > gas_target
  → next_l2_gas_price = 110 fri  (EIP-1559 increase)

User submits AllResources V3 tx with max_l2_gas_price = 100 fri.

Gateway validate_resource_bounds:
  threshold = 100% × 100 = 100
  100 >= 100  → PASS

Gateway run_validate_entry_point (blockifier, old block_info):
  check_fee_bounds: 100 >= 100  → PASS
  → tx admitted to mempool

Batcher executes tx with block L2 gas price = 110 fri:
  check_fee_bounds: 100 < 110  → FAIL MaxGasPriceTooLow
  → tx reverts; user pays fees for a failed tx

---

Previous block: l2_gas_price = 100 fri, gas_used < gas_target
  → next_l2_gas_price = 90 fri  (EIP-1559 decrease)

User submits AllResources V3 tx with max_l2_gas_price = 90 fri.

Gateway validate_resource_bounds:
  threshold = 100% × 100 = 100
  90 < 100  → FAIL GAS_PRICE_TOO_LOW
  → tx rejected

Batcher would have executed tx with block L2 gas price = 90 fri:
  check_fee_bounds: 90 >= 90  → would PASS
  → valid tx incorrectly rejected at gateway
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L364-390)
```rust
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
```

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/apollo_batcher/src/batcher.rs (L375-379)
```rust
        mempool_client
            .update_gas_price(
                propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
            )
            .await
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
