### Title
Gateway `validate_resource_bounds` checks against stale `l2_gas_price` instead of `next_l2_gas_price`, admitting transactions that will fail at blockifier pre-validation — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful admission check validates a transaction's `max_price_per_unit` against the **current** block's `l2_gas_price`. However, the transaction will be executed in the **next** block, which uses `next_l2_gas_price` as its L2 gas price. Under EIP-1559 dynamics, whenever a block's gas usage exceeds the gas target, `next_l2_gas_price > l2_gas_price`. Transactions with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` pass gateway admission but are rejected by the blockifier's `check_fee_bounds` pre-validation, causing the gateway to admit transactions that will never execute.

The code itself contains an explicit acknowledgment of this bug: `// TODO(Arni): getnext_l2_gas_price from the block header.`

### Finding Description

In `validate_resource_bounds`, the gateway reads the L2 gas price from the **current** block's `BlockInfo`:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `BlockInfo.gas_prices.strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` — the **current** block's price — and does not expose `block_header.next_l2_gas_price`:

```rust
strk_gas_prices: GasPriceVector {
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
    ...
},
``` [2](#0-1) 

`BlockHeaderWithoutHash` carries both fields, but only `l2_gas_price` is forwarded into `BlockInfo`:

```rust
pub l2_gas_price: GasPricePerToken,
pub l2_gas_consumed: GasAmount,
pub next_l2_gas_price: GasPrice,   // ← never propagated to BlockInfo
``` [3](#0-2) 

The threshold check in `validate_tx_l2_gas_price_within_threshold` computes:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...); }
``` [4](#0-3) 

With the default `min_gas_price_percentage = 100`, the threshold equals `block_N.l2_gas_price` exactly. A transaction with `max_price_per_unit = block_N.l2_gas_price` passes this check.

However, the blockifier's `check_fee_bounds` (called in `perform_pre_validation_stage`) checks the transaction's `max_price_per_unit` against the **actual block's** L2 gas price — which for block N+1 is `block_N.next_l2_gas_price`:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

The EIP-1559 formula in `calculate_next_base_gas_price` increases `next_l2_gas_price` above `l2_gas_price` whenever `gas_used > gas_target`:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [6](#0-5) 

This is a normal operating condition on a busy network.

### Impact Explanation

Any transaction with `max_price_per_unit` in the range `[block_N.l2_gas_price, block_N.next_l2_gas_price)` passes gateway admission and enters the mempool, but is rejected by the blockifier at pre-validation with `MaxGasPriceTooLow`. The sequencer wastes resources attempting to execute these transactions. An attacker who observes the current gas price can deliberately craft transactions that pass the gateway check but fail at execution, polluting the mempool and consuming sequencer CPU without paying fees (since pre-validation failures do not charge fees).

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The condition `next_l2_gas_price > l2_gas_price` occurs whenever a block's gas usage exceeds the gas target — a routine condition on a loaded network. The gap between the two prices grows proportionally to how far above the target the block is. The TODO comment in the production code confirms the developers are aware the wrong field is being used.

### Recommendation

Expose `next_l2_gas_price` from `BlockHeaderWithoutHash` through the `GatewayFixedBlockStateReader` interface (or add it to `BlockInfo`), and use it in `validate_resource_bounds` instead of `l2_gas_price`:

```rust
// Use next_l2_gas_price (the price for the block this tx will execute in)
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_next_l2_gas_price()   // new method
    .await?;
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    next_block_l2_gas_price,
)?;
```

### Proof of Concept

1. Observe block N with `l2_gas_price = P` and `next_l2_gas_price = P' > P` (block N was above gas target).
2. Submit an invoke V3 transaction with `AllResources` bounds where `l2_gas.max_price_per_unit = P`.
3. Gateway calls `validate_resource_bounds`: threshold = `100% * P = P`; `max_price_per_unit = P >= P` → **accepted**, transaction enters mempool.
4. Sequencer builds block N+1 with `l2_gas_price = P'`.
5. Blockifier calls `check_fee_bounds`: `max_price_per_unit = P < P' = actual_gas_price` → `MaxGasPriceTooLow` → **rejected at pre-validation, no fee charged**.
6. Transaction is discarded after consuming sequencer resources. Repeat at scale for mempool DoS.

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L36-57)
```rust
        let block_info = BlockInfo {
            block_number: block_header.block_number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_wei.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_wei.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_wei.try_into()?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
            },
            use_kzg_da: block_header.l1_da_mode.is_use_kzg_da(),
            starknet_version: block_header.starknet_version,
        };

        Ok(block_info)
    }
```

**File:** crates/starknet_api/src/block.rs (L237-239)
```rust
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L128-130)
```rust
    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

```
