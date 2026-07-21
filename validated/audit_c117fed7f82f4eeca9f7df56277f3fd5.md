### Title
Gateway stateful validator compares transaction L2 gas price against the current block's `l2_gas_price` instead of the block header's `next_l2_gas_price`, causing incorrect admission decisions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `gas_prices.strk_gas_prices.l2_gas_price` from the previous block's `BlockInfo` as the reference price for the L2 gas threshold check. The correct reference is `next_l2_gas_price` stored in the same block's header — the EIP-1559-computed price that will actually govern the *next* block. The code itself carries an explicit acknowledgement of this error in a TODO comment. The mismatch causes the gateway to admit transactions that will be rejected by the blockifier at execution time (when the price is rising) and to reject valid transactions (when the price is falling).

---

### Finding Description

In `validate_resource_bounds`:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;          // ← price of the *previous* block, not the next block
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,
)?;
``` [1](#0-0) 

The value obtained is `BlockInfo::gas_prices.strk_gas_prices.l2_gas_price`, which is the price at which transactions in the *already-committed* block were executed. The block header separately stores `next_l2_gas_price` — the EIP-1559-adjusted price for the *upcoming* block:

```rust
pub l2_gas_price: GasPricePerToken,   // price for this block
pub next_l2_gas_price: GasPrice,      // price for the NEXT block  ← correct reference
``` [2](#0-1) 

The threshold computed in `validate_tx_l2_gas_price_within_threshold` is:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
``` [3](#0-2) 

When the batcher later builds the block, it uses `next_l2_gas_price` (from the previous block header) as the block's actual L2 gas price. The blockifier's `check_fee_bounds` then enforces:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [4](#0-3) 

The gateway validates against `l2_gas_price`; the blockifier enforces against `next_l2_gas_price`. These two values diverge every block via the EIP-1559 adjustment in `calculate_next_base_gas_price`:

```rust
let price_change = (price_u256 * gas_delta) / denominator;
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [5](#0-4) 

The `next_l2_gas_price` field is propagated through the block header and is accessible from the block header but not from the `BlockInfo` struct returned by `get_block_info()`, which is why the code falls back to the wrong field. [6](#0-5) 

---

### Impact Explanation

**Incorrect admission (price rising — congested network):**  
When `next_l2_gas_price > l2_gas_price`, the gateway threshold is too low. A transaction with `max_price_per_unit` satisfying:

```
(min_gas_price_percentage/100) × l2_gas_price  ≤  tx_price  <  (min_gas_price_percentage/100) × next_l2_gas_price
```

passes the gateway's `validate_resource_bounds` check and enters the mempool, but is then rejected by the blockifier's `check_fee_bounds` at execution time with `MaxGasPriceTooLow`. The transaction consumes mempool capacity and batcher processing time without ever executing.

**Incorrect rejection (price falling — under-utilized network):**  
When `next_l2_gas_price < l2_gas_price`, the gateway threshold is too high. Transactions whose `max_price_per_unit` would satisfy the blockifier's actual price check are rejected at the gateway, denying service to legitimate users.

Both directions match the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block. During any period of sustained congestion or sustained low activity, `next_l2_gas_price` diverges from `l2_gas_price` by up to `1/gas_price_max_change_denominator` per block. The discrepancy is permanent and grows monotonically until the price stabilises. No special attacker capability is required — any user submitting a transaction during a price-change period is affected. The TODO comment in the production code confirms the developers are aware the wrong field is being read.

---

### Recommendation

Replace the `l2_gas_price` field read with `next_l2_gas_price` from the block header. The `GatewayFixedBlockStateReader` trait should be extended to expose `next_l2_gas_price`, or a dedicated method (e.g., `get_next_l2_gas_price`) should be added. The same correction should be applied to `run_validate_entry_point`, which builds a `BlockContext` using the same stale `block_info` without updating the L2 gas price to `next_l2_gas_price`.

---

### Proof of Concept

**Setup:**
- Previous committed block: `l2_gas_price = 1_000_000_000`, `next_l2_gas_price = 1_030_000_000` (3% increase due to congestion, within EIP-1559 bounds)
- `min_gas_price_percentage = 100`

**Gateway threshold (wrong):**
```
threshold = 100% × 1_000_000_000 = 1_000_000_000
```

**Correct threshold:**
```
threshold = 100% × 1_030_000_000 = 1_030_000_000
```

**Attacker submits a transaction with `l2_gas.max_price_per_unit = 1_010_000_000`:**

1. `StatelessTransactionValidator::validate_resource_bounds` — passes (price ≥ `min_gas_price` config).
2. `StatefulTransactionValidator::validate_resource_bounds` — passes: `1_010_000_000 ≥ 1_000_000_000`.
3. Transaction enters the mempool.
4. Batcher builds the next block with `l2_gas_price = next_l2_gas_price = 1_030_000_000`.
5. `AccountTransaction::perform_pre_validation_stage` → `check_fee_bounds` → `1_010_000_000 < 1_030_000_000` → `MaxGasPriceTooLow` error.
6. Transaction is rejected at execution, having consumed gateway and mempool resources.

By repeating this with many transactions, an attacker can fill the mempool with transactions that will never execute, degrading sequencer throughput.

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

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/apollo_protobuf/src/converters/header.rs (L290-292)
```rust
            l2_gas_consumed: header.block_header_without_hash.l2_gas_consumed.0,
            next_l2_gas_price: Some(header.block_header_without_hash.next_l2_gas_price.0.into()),
            fee_proposal_fri: header
```
