### Title
Gateway Stateful Validator Uses Previous Block's L2 Gas Price as Admission Threshold, Admitting Transactions That Will Fail at Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `StatefulTransactionValidator::validate_resource_bounds` function gates mempool admission using the **previous** committed block's L2 gas price as the threshold. Because the actual next block's L2 gas price is computed by the EIP-1559 mechanism and can be materially higher, transactions whose `max_price_per_unit` sits between the previous and next block's price pass every gateway check yet are rejected by the batcher's blockifier during pre-validation. Since no fee is charged for pre-validation failures, an unprivileged attacker can flood the mempool with zero-cost invalid transactions.

### Finding Description

`validate_resource_bounds` reads the L2 gas price from the **latest committed block** via `gateway_fixed_block_state_reader.get_block_info()` and passes it to `validate_tx_l2_gas_price_within_threshold`:

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

The threshold is `min_gas_price_percentage% × previous_block_l2_gas_price` (default 100 %): [2](#0-1) 

`run_validate_entry_point` — the blockifier pre-validation step that also runs at the gateway — constructs its `BlockContext` from the same previous block info (only incrementing the block number):

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [3](#0-2) 

So both gateway checks use `P_prev`. The batcher, however, builds the next block with a price `P_next` computed by the EIP-1559 `calculate_next_base_gas_price` function: [4](#0-3) 

When the previous block consumed gas above the target, `P_next > P_prev`. A transaction with `max_price_per_unit = P_prev` satisfies both gateway checks but fails the blockifier's `check_fee_bounds` inside `perform_pre_validation_stage` at execution time: [5](#0-4) 

Because `perform_pre_validation_stage` failure does not charge a fee, the attacker bears zero cost per rejected transaction.

The TODO comment in the source explicitly acknowledges the wrong reference value is used: [6](#0-5) 

The default production configuration sets `min_gas_price_percentage = 100`, meaning the threshold equals exactly `P_prev` with no buffer: [7](#0-6) 

### Impact Explanation

An attacker can continuously submit V3 `AllResources` transactions with `l2_gas.max_price_per_unit = P_prev` during any period when the network is above the gas target (i.e., whenever `P_next > P_prev`). Each transaction:

1. Passes `validate_resource_bounds` (price ≥ threshold).
2. Passes `run_validate_entry_point` blockifier validation (gateway uses `P_prev`).
3. Enters the mempool.
4. Is picked up by the batcher, fails `check_fee_bounds` with `MaxGasPriceTooLow`, and is dropped — **without charging any fee**.

The attacker can saturate the mempool at zero cost, displacing legitimate transactions and degrading liveness. The symmetric false-rejection case (when `P_next < P_prev`) causes valid user transactions to be incorrectly rejected at the gateway.

### Likelihood Explanation

Any unprivileged user can trigger this. The condition `P_next > P_prev` holds whenever the previous block's gas consumption exceeded the EIP-1559 target — a routine occurrence during normal network load. No special account, key, or privileged role is required.

### Recommendation

Replace the previous block's L2 gas price with the **computed next block's L2 gas price** as the admission threshold. The orchestrator already exposes `calculate_next_base_gas_price` / `calculate_next_l2_gas_price_for_fin`; the gateway should call the same logic (or receive the pre-computed value via the block header) so that the admission threshold matches the price the batcher will actually enforce.

### Proof of Concept

```
Let P_prev = 100 FRI  (previous block L2 gas price)
Let P_next = 112 FRI  (next block, previous block was above gas target)

Attacker submits: AllResources { l2_gas: { max_price_per_unit: 100, max_amount: X } }

Gateway validate_resource_bounds:  100 >= 100%×100 = 100  → PASS
Gateway run_validate_entry_point:  block_context uses P_prev=100, 100 >= 100 → PASS
Transaction enters mempool.

Batcher executes with P_next=112:
  check_fee_bounds: 100 < 112 → MaxGasPriceTooLow → REJECTED, no fee charged.

Attacker repeats with a new nonce at zero cost, filling the mempool.
```

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
