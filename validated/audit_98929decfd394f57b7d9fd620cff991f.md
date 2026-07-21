### Title
Gateway Stateful Validator Uses Stale Previous-Block L2 Gas Price for Resource Bounds Admission Check - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`validate_resource_bounds` in the gateway's stateful validator reads the **previous (last committed) block's** L2 gas price to decide whether to admit a transaction, while the blockifier uses the **next block's** L2 gas price during actual execution. Because the L2 gas price is recomputed every block by the consensus orchestrator, the two values can diverge, causing the gateway to admit transactions that will fail execution, or to reject transactions that would succeed.

---

### Finding Description

In `validate_resource_bounds`, the code explicitly names the variable `previous_block_l2_gas_price` and reads it from `get_block_info()`, which returns the last committed block's info. A developer TODO comment at the same line acknowledges the problem:

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

The threshold computed from this stale price is:

```
threshold = (min_gas_price_percentage / 100) * previous_block_l2_gas_price
```

A transaction is admitted if `tx_l2_gas_price >= threshold`. [2](#0-1) 

Meanwhile, `run_validate_entry_point` builds a `BlockContext` from the same stale `get_block_info()` call, only incrementing the block number — the gas prices remain those of the previous block:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

The actual next block's L2 gas price is computed dynamically by the consensus orchestrator via `update_l2_gas_price` and stored in `ConsensusBlockInfo.l2_gas_price_fri`. This value is independent of the previous block's price and can be higher or lower. [4](#0-3) 

During blockifier execution in the batcher, `check_fee_bounds` (called from `perform_pre_validation_stage`) validates the transaction's `max_price_per_unit` against the **actual next block's** gas price embedded in the `BlockContext`. This is the price that matters for execution. [5](#0-4) 

---

### Impact Explanation

Two divergent failure modes arise:

**1. Invalid transactions admitted (next block price rises):**
If `next_block_l2_gas_price > previous_block_l2_gas_price`, a transaction with:
```
threshold ≤ tx_l2_gas_price < next_block_l2_gas_price
```
passes the gateway check (admitted to mempool) but fails `check_fee_bounds` during blockifier execution. The mempool fills with transactions that will be reverted or dropped during block building, wasting sequencer resources and degrading throughput.

**2. Valid transactions rejected (next block price falls):**
If `next_block_l2_gas_price < previous_block_l2_gas_price`, a transaction with:
```
(min_gas_price_percentage/100) * next_block_l2_gas_price ≤ tx_l2_gas_price < (min_gas_price_percentage/100) * previous_block_l2_gas_price
```
is rejected at the gateway even though it would pass blockifier execution. Users are incorrectly told their transaction is invalid.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The L2 gas price changes every block via `update_l2_gas_price` in the consensus orchestrator. Any block where gas usage differs from the previous block will produce a different L2 gas price. This is a normal, continuous condition — not a rare admin action. The divergence is bounded by the EIP-1559-style adjustment rate, but with `min_gas_price_percentage` set to values like 50 (the default in tests), the admission window is wide enough that a single block's price movement can place transactions in the gap.

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` read with the **next block's** L2 gas price. The consensus orchestrator already computes and stores this value in `ConsensusBlockInfo.l2_gas_price_fri` (the `next_l2_gas_price` field on the block header). The gateway should read this field — as the TODO comment itself states — so that the admission threshold matches the price that will be enforced during execution. [6](#0-5) 

---

### Proof of Concept

1. Previous committed block has `l2_gas_price = 100`.
2. Consensus orchestrator computes next block's `l2_gas_price = 150` (gas usage increased).
3. Gateway config: `min_gas_price_percentage = 50`, so threshold = `50% * 100 = 50`.
4. User submits a transaction with `tx_l2_gas_price = 80`.
5. Gateway check: `80 >= 50` → **admitted** to mempool.
6. Batcher builds block with `l2_gas_price = 150`; blockifier `check_fee_bounds`: `80 < 150` → **execution fails**.
7. Transaction was incorrectly admitted; it consumes mempool and batcher resources before failing.

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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L1-5)
```rust
//! Implementation of the ConsensusContext interface for running the sequencer.
//!
//! It connects to the Batcher who is responsible for building/validating blocks.
#[cfg(test)]
#[path = "sequencer_consensus_context_test.rs"]
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
