### Title
Gateway stateful validator rejects valid V3 transactions when L2 gas price decreases between blocks due to stale previous-block price anchor - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`validate_tx_l2_gas_price_within_threshold` anchors its admission floor to the **previous block's** L2 gas price. With the production default `min_gas_price_percentage = 100`, every incoming `AllResources` (V3) transaction must offer a `max_price_per_unit` ≥ 100 % of the previous block's price. Because the EIP-1559-style fee market in `calculate_next_base_gas_price` can lower the base price whenever gas usage falls below target, any block-to-block price decrease causes the gateway to reject V3 transactions whose `max_price_per_unit` reflects the current (lower) market rate. Legacy `L1Gas` transactions are entirely exempt from this check. A developer TODO in the source code explicitly acknowledges the stale reference: `// TODO(Arni): getnext_l2_gas_price from the block header.`

### Finding Description

**Admission check (stateful validator)**

`validate_resource_bounds` fetches the previous block's `strk_gas_prices.l2_gas_price` and forwards it to `validate_tx_l2_gas_price_within_threshold`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;                          // ← previous block, not next
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,
)?;
``` [1](#0-0) 

The threshold computation:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(StarknetError { ... "GAS_PRICE_TOO_LOW" ... });
}
``` [2](#0-1) 

With the production default `min_gas_price_percentage = 100`, the threshold equals the previous block's price exactly. [3](#0-2) 

**Fee market can decrease the price**

`calculate_next_base_gas_price` lowers the price whenever `gas_used ≤ gas_target`:

```rust
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change }
    else { price_u256 - price_change };
``` [4](#0-3) 

An empty or lightly-loaded block can therefore produce a next-block price that is strictly less than the previous block's price.

**Asymmetry: legacy transactions are exempt**

The check is skipped entirely for `ValidResourceBounds::L1Gas`:

```rust
ValidResourceBounds::L1Gas(_) => {
    // No validation required for legacy transactions.
}
``` [5](#0-4) 

**Developer acknowledgement of the stale reference**

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    ...
``` [6](#0-5) 

The intended reference is the **next** block's price, not the previous block's price. The current code uses the wrong anchor.

### Impact Explanation

Any V3 (`AllResources`) transaction whose `max_price_per_unit` is set to the current market rate (i.e., the next block's price) is rejected at the gateway whenever the fee market has decreased the price since the previous block. The transaction is structurally valid and would be accepted by the blockifier; the gateway's stale-price check is the sole cause of rejection. This satisfies the stated High impact: **"Mempool/gateway/RPC admission rejects valid transactions before sequencing."**

Because legacy `L1Gas

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-240)
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

**File:** crates/apollo_gateway_config/src/config.rs (L289-300)
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
}
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L128-130)
```rust
    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

```
