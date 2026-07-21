### Title
Gateway Stateful Validator Checks `l2_gas_price` of the Committed Block Instead of `next_l2_gas_price` for Resource Bounds Admission — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` gates admission on the *current* committed block's `l2_gas_price`, but every transaction admitted to the mempool will be executed in the *next* block at `next_l2_gas_price`. Because the EIP-1559 fee market continuously adjusts the price, the two values diverge whenever block utilization deviates from the gas target. The mismatch causes the gateway to admit transactions that will fail at blockifier execution (price rising) and to reject transactions that would succeed (price falling). The code itself acknowledges the bug with an explicit `TODO`.

### Finding Description

In `validate_resource_bounds` the gateway reads the L2 gas price to use as the admission threshold:

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

The value read is `BlockInfo::gas_prices.strk_gas_prices.l2_gas_price`, which is the price that was *active during* the latest committed block. This is populated by `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` directly from `block_header.l2_gas_price`:

```rust
l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
``` [2](#0-1) 

However, the EIP-1559 fee market computes a *different* price for the next block — `next_l2_gas_price` — at finalization time via `calculate_next_l2_gas_price_for_fin`, and stores it in `StorageBlockHeader::next_l2_gas_price`: [3](#0-2) 

The blockifier's pre-validation stage (`check_fee_bounds`) compares the transaction's `max_price_per_unit` against the *block context* gas price, which is set to `next_l2_gas_price` for the incoming block: [4](#0-3) 

The gateway and the blockifier therefore use two different reference prices. The `TODO` comment at line 229 explicitly acknowledges the correct value is `next_l2_gas_price`.

The `validate_tx_l2_gas_price_within_threshold` function then enforces:

```
tx.l2_gas.max_price_per_unit >= (min_gas_price_percentage / 100) * previous_block.l2_gas_price
``` [5](#0-4) 

With the default `min_gas_price_percentage = 100`, the threshold equals `previous_block.l2_gas_price` exactly, not `next_l2_gas_price`.

### Impact Explanation

**Case 1 — False admission (congested network):** When `gas_used > gas_target`, `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` passes the gateway check but fails the blockifier's `check_fee_bounds` with `MaxGasPriceTooLow`. The transaction enters the mempool, consumes sequencer resources, and is ultimately dropped or reverted — matching the impact "Mempool/gateway/RPC admission accepts invalid transactions."

**Case 2 — False rejection (under-utilized network):** When `gas_used < gas_target`, `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, l2_gas_price)` is rejected by the gateway even though it would pass blockifier validation and execute successfully — matching the impact "Mempool/gateway/RPC admission rejects valid transactions before sequencing."

### Likelihood Explanation

The EIP-1559 mechanism adjusts the price every block. Any block that is not exactly at the gas target produces `next_l2_gas_price ≠ l2_gas_price`. This is the normal operating condition; the invariant is violated on virtually every block.

### Recommendation

In `validate_resource_bounds`, retrieve `next_l2_gas_price` from the block header rather than `l2_gas_price`. Either:

1. Extend `GatewayFixedBlockStateReader::get_block_info` to populate a field carrying `next_l2_gas_price`, or
2. Add a dedicated `get_next_l2_gas_price` method to `GatewayFixedBlockStateReader` that reads `block_header_without_hash.next_l2_gas_price` from the sync client.

The threshold comparison in `validate_tx_l2_gas_price_within_threshold` should then use this value instead of `previous_block_l2_gas_price`.

### Proof of Concept

**Congested-network scenario (false admission):**

1. Latest committed block: `l2_gas_price = 100 FRI`, `gas_used > gas_target` → `next_l2_gas_price = 110 FRI`.
2. User submits an invoke transaction with `l2_gas.max_price_per_unit = 105`.
3. Gateway check (`min_gas_price_percentage = 100`): `105 ≥ 100` → **ADMITTED**.
4. Blockifier pre-validation for the next block (price = 110): `105 < 110` → **`MaxGasPriceTooLow`**.
5. Transaction occupies a mempool slot and is eventually discarded, wasting sequencer resources.

**Under-utilized-network scenario (false rejection):**

1. Latest committed block: `l2_gas_price = 100 FRI`, `gas_used < gas_target` → `next_l2_gas_price = 90 FRI`.
2. User submits an invoke transaction with `l2_gas.max_price_per_unit = 95`.
3. Gateway check: `95 < 100` → **REJECTED** with `GAS_PRICE_TOO_LOW`.
4. Blockifier would check: `95 ≥ 90` → would **PASS**.
5. A valid, economically sound transaction is incorrectly denied admission.

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L48-49)
```rust
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
```

**File:** crates/apollo_storage/src/header.rs (L88-89)
```rust
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
