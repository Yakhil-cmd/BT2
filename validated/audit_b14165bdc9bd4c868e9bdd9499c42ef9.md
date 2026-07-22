### Title
Gateway L2 Gas Price Admission Check Uses Previous Block's `l2_gas_price` Instead of `next_l2_gas_price` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's stateful admission check validates a transaction's `max_price_per_unit` against the **previous block's** `l2_gas_price` instead of the **next block's** `next_l2_gas_price`. Because the transaction will be executed in the next block (which uses `next_l2_gas_price`), the wrong temporal reference is used. This causes the gateway to admit transactions that will fail blockifier pre-validation (when the price is rising) and to reject transactions that are actually valid (when the price is falling). The code itself contains a TODO acknowledging the bug.

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price from the latest committed block:

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

The field read is `l2_gas_price` — the price that was used **in** the previous block. However, the block header also stores a separate `next_l2_gas_price` field, which is the price that will be applied to the **next** block (the one being built). These two values diverge whenever the EIP-1559-style price adjustment algorithm runs:

```rust
let block_header_without_hash = BlockHeaderWithoutHash {
    l2_gas_price,
    next_l2_gas_price: self.l2_gas_price,   // ← different field
    ...
};
``` [2](#0-1) 

The `next_l2_gas_price` is computed by `calculate_next_l2_gas_price` and stored in the block header, but the gateway never reads it — it reads the stale `l2_gas_price` instead. [3](#0-2) 

The threshold comparison in `validate_tx_l2_gas_price_within_threshold` then rejects or accepts based on this wrong reference value:

```rust
if tx_l2_gas_price.0 < threshold {   // threshold derived from wrong price
    return Err(...GAS_PRICE_TOO_LOW...);
}
``` [4](#0-3) 

Meanwhile, the blockifier's `check_fee_bounds` in `perform_pre_validation_stage` correctly uses the actual block's gas prices (which will be `next_l2_gas_price`):

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

This creates a split-brain between gateway admission and blockifier execution.

### Impact Explanation

**When `next_l2_gas_price > l2_gas_price` (price rising — the normal case under load):**

A user submits a transaction with `max_price_per_unit = l2_gas_price` (exactly the previous block's price). The gateway threshold check passes (`tx_price >= previous_block_price`). The transaction is admitted to the mempool. When the batcher picks it up and the blockifier runs `check_fee_bounds` against `next_l2_gas_price`, the check fails with `MaxGasPriceTooLow`. The transaction fails pre-validation — it is a pre-validation error, so no fee is charged. The sequencer has wasted resources admitting, storing, and attempting to execute an invalid transaction.

**When `next_l2_gas_price < l2_gas_price` (price falling):**

A user submits a transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price)`. The gateway rejects it with `GAS_PRICE_TOO_LOW` even though the transaction would succeed at execution. Valid transactions are incorrectly rejected at the admission layer.

Both branches match the "High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing" impact.

### Likelihood Explanation

The L2 gas price is adjusted every block via an EIP-1559-style algorithm. Any block where gas usage differs from the target causes `next_l2_gas_price ≠ l2_gas_price`. Under normal network load this divergence is small but non-zero. During congestion the divergence grows. Any user who sets `max_price_per_unit` to exactly the previous block's price (a natural choice, e.g. from a fee estimator that reads the last block) will trigger the admission/execution mismatch. No special privileges are required.

### Recommendation

Replace the read of `l2_gas_price` with `next_l2_gas_price` from the block header. The `BlockHeaderWithoutHash` already stores this field. The `GatewayFixedBlockStateReader` interface should expose it (or return the full `BlockHeaderWithoutHash`), and `validate_resource_bounds` should use it:

```rust
// Use next_l2_gas_price, not l2_gas_price
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_header()   // expose next_l2_gas_price
    .await?
    .next_l2_gas_price;
```

The existing TODO comment in the code (`// TODO(Arni): getnext_l2_gas_price from the block header.`) already identifies this fix. [6](#0-5) 

### Proof of Concept

1. Observe the previous committed block has `l2_gas_price = P` and `next_l2_gas_price = P'` where `P' > P` (rising price, e.g. after a congested block).
2. Submit an invoke transaction with `resource_bounds.l2_gas.max_price_per_unit = P`.
3. Gateway `validate_resource_bounds` computes `threshold = P * min_gas_price_percentage / 100`. With default `min_gas_price_percentage = 100`, `threshold = P`. The check `P >= P` passes. Transaction is admitted to the mempool.
4. Batcher picks the transaction. Blockifier runs `check_fee_bounds` with the actual block's `l2_gas_price = P'`. Check `P >= P'` fails (`P < P'`). Transaction fails with `MaxGasPriceTooLow` pre-validation error. No fee is charged. Sequencer resources are wasted. [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L425-441)
```rust
    /// Returns the next L2 gas price without mutating context. Used when building the fin and when
    /// updating at decision time.
    fn calculate_next_l2_gas_price(&self, height: BlockNumber, l2_gas_used: GasAmount) -> GasPrice {
        let fee_actual = compute_fee_actual(
            &self.fee_proposals_window,
            height,
            VersionedConstants::latest_constants().fee_proposal_window_size,
        );
        calculate_next_l2_gas_price_for_fin(
            self.l2_gas_price,
            height,
            l2_gas_used,
            self.config.dynamic_config.override_l2_gas_price_fri,
            &self.config.dynamic_config.min_l2_gas_price_per_height,
            fee_actual,
        )
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
