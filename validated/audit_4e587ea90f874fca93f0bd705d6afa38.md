### Title
Gateway Stateful Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing False Admissions and False Rejections - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds check compares a transaction's `l2_gas.max_price_per_unit` against the **current block's** `l2_gas_price`, but the transaction will actually be executed in the **next block** whose L2 gas price is computed by the EIP-1559 mechanism and stored as `next_l2_gas_price` in the block header. This one-block lag produces two symmetric admission errors: (1) transactions that pass the gateway check but will be rejected at execution (false admission), and (2) transactions that are rejected at the gateway but would succeed at execution (false rejection). A developer TODO comment in the code explicitly acknowledges the wrong field is being read.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads the L2 gas price reference from the latest committed block:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:229-236
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
```

It then enforces:

```rust
// lines 367-372
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...); }
```

The field read is `strk_gas_prices.l2_gas_price` — the price **used in the current block**. The block header also carries a separate `next_l2_gas_price` field (the EIP-1559-adjusted price for the **next** block, computed by `calculate_next_base_gas_price`). This is the price the batcher will actually place in the block context when the transaction executes.

The batcher's `get_block_info` builds the execution block context from the committed header's gas prices:

```rust
// crates/apollo_batcher/src/batcher.rs:703-713
gas_prices: GasPrices {
    strk_gas_prices: GasPriceVector {
        l1_gas_price: convert_price(header.l1_gas_price.price_in_fri)?,
        l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_fri)?,
        l2_gas_price: convert_price(header.l2_gas_price.price_in_fri)?,
    },
    ...
```

But the **next** block's L2 gas price is `header.next_l2_gas_price` (visible in the block JSON at `"next_l2_gas_price": "0x1dcd65000"`), which is what the sequencer consensus context sets via `update_l2_gas_price` → `calculate_next_l2_gas_price_for_fin` → `calculate_next_base_gas_price`. The EIP-1559 formula can move the price by up to `price / gas_price_max_change_denominator` per block in either direction.

**False-admission path (next price > current price):**
When the current block is above the gas target, `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit = l2_gas_price` satisfies the gateway threshold (100% of current price) and is admitted to the mempool. When the batcher executes it in the next block, `check_fee_bounds` compares against `next_l2_gas_price` and rejects it with `MaxGasPriceTooLow`. The gateway has admitted a transaction that cannot execute.

**False-rejection path (next price < current price):**
When the current block is below the gas target, `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit = next_l2_gas_price` would succeed at execution, but the gateway rejects it because `max_price_per_unit < threshold% * l2_gas_price`. A valid transaction is denied service.

### Impact Explanation

**False admission** — the gateway accepts transactions that will fail at blockifier execution. This allows an unprivileged sender to flood the mempool and batcher with transactions that consume validation resources (signature check, nonce lookup, blockifier pre-validation) but produce no useful block content. The admission decision is wrong.

**False rejection** — the gateway rejects transactions that would succeed at execution. Users whose wallets set `max_price_per_unit` to the upcoming block's price (e.g., from `starknet_estimateFee`) are denied service whenever the current block is above the gas target and the price is falling.

Both outcomes match: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block based on gas usage. Any block that is not exactly at the gas target produces a non-zero delta between `l2_gas_price` and `next_l2_gas_price`. In practice, blocks are rarely exactly at target, so the discrepancy is present in nearly every block. The magnitude is bounded by `1/gas_price_max_change_denominator` per block but is systematic and predictable. The production deployment config sets `min_gas_price_percentage = 100`, making the threshold exactly equal to the stale price, maximising the window for both false admissions and false rejections.

### Recommendation

Replace the read of `strk_gas_prices.l2_gas_price` with the `next_l2_gas_price` field from the block header, as the TODO comment already identifies:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let next_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .next_l2_gas_price;   // use the EIP-1559-adjusted price for the next block
```

This ensures the gateway's admission threshold matches the price the transaction will actually face at execution.

### Proof of Concept

1. Observe the current committed block has `l2_gas_price = P` and `next_l2_gas_price = P * (1 + δ)` where `δ > 0` (block was above gas target).
2. Submit an `InvokeV3` transaction with `l2_gas.max_price_per_unit = P` and `l2_gas.max_amount` sufficient to cover execution.
3. Gateway `validate_resource_bounds` computes `threshold = 100% * P = P`; the transaction satisfies `P >= P` and is admitted.
4. The batcher places the transaction in the next block with `l2_gas_price = P * (1 + δ)`.
5. `AccountTransaction::check_fee_bounds` evaluates `P < P * (1 + δ)` → `MaxGasPriceTooLow` → transaction reverts or is rejected.
6. The gateway has admitted a transaction that cannot execute, wasting sequencer resources.

Repeat at scale to exhaust mempool capacity or batcher execution budget with zero-cost (no fee charged on rejected transactions) spam.

---

**Key code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L227-240)
```rust
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

**File:** crates/apollo_batcher/src/batcher.rs (L699-717)
```rust
        Ok(BlockInfo {
            block_number: header.block_number,
            block_timestamp: header.timestamp,
            sequencer_address: header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_wei)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_wei)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_wei)?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: convert_price(header.l1_gas_price.price_in_fri)?,
                    l1_data_gas_price: convert_price(header.l1_data_gas_price.price_in_fri)?,
                    l2_gas_price: convert_price(header.l2_gas_price.price_in_fri)?,
                },
            },
            use_kzg_da: header.l1_da_mode.is_use_kzg_da(),
            starknet_version: header.starknet_version,
        })
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

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
