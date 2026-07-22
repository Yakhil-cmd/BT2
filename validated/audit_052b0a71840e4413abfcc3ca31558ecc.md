### Title
Gateway Stateful Validator Uses Previous Block's L2 Gas Price Instead of Next Block's Price for Admission Check - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The gateway's stateful resource-bounds check compares a transaction's `l2_gas.max_price_per_unit` against the **previous committed block's** L2 gas price, but the transaction will actually be executed against the **next block's** L2 gas price (computed by the EIP-1559 fee market). The code itself carries an explicit TODO acknowledging the wrong value is used. This mismatch causes the gateway to admit transactions that will fail at execution (when the next block price is higher) and to reject transactions that would succeed (when the next block price is lower).

### Finding Description

In `validate_resource_bounds`, the gateway fetches the latest committed block's info and uses its `strk_gas_prices.l2_gas_price` as the reference price:

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

The threshold enforced is:

```
tx.l2_gas.max_price_per_unit >= (min_gas_price_percentage / 100) * previous_block_l2_gas_price
``` [2](#0-1) 

However, the actual price used when the batcher executes the transaction is the **next block's** L2 gas price, computed by the EIP-1559 fee market (`calculate_next_base_gas_price`) from the current block's gas consumption:

```rust
pub fn calculate_next_base_gas_price(
    price: GasPrice,
    gas_used: GasAmount,
    gas_target: GasAmount,
    min_gas_price: GasPrice,
) -> GasPrice { ... }
``` [3](#0-2) 

The fee market can move the price up or down each block. Test snapshots show changes of roughly 1% per block under high/low congestion: [4](#0-3) 

The `GatewayFixedBlockSyncStateClient` always returns the latest **committed** block's info, not the pending next block: [5](#0-4) 

The `run_validate_entry_point` path increments the block number but does **not** recompute the L2 gas price for the next block — it reuses the same `block_info` from the committed block: [6](#0-5) 

### Impact Explanation

**Scenario A — next block price rises (congestion increasing):**
A user submits a V3 `AllResources` transaction with `l2_gas.max_price_per_unit = P_prev * threshold_pct / 100`. The gateway admits it because `P_prev` satisfies the check. The batcher executes it at `P_next > P_prev`. The blockifier's `check_fee_bounds` rejects it with `MaxGasPriceTooLow`, the transaction is reverted, and the sequencer has wasted execution resources on a transaction that was predictably invalid. An attacker who can observe the current block's gas usage can reliably craft transactions that pass gateway admission but fail at execution.

**Scenario B — next block price falls (congestion decreasing):**
A user submits a transaction with `l2_gas.max_price_per_unit = P_next` where `P_next < P_prev * threshold_pct / 100`. The gateway rejects it with `GAS_PRICE_TOO_LOW` even though the transaction would succeed at execution. Valid transactions are incorrectly denied admission.

Both scenarios are reachable by any unprivileged user submitting a standard V3 invoke transaction with `ValidResourceBounds::AllResources`.

### Likelihood Explanation

The L2 gas price is dynamic and changes every block. Under normal network conditions with variable load, the price will routinely differ between the committed block and the next block. The `validate_resource_bounds` flag is enabled by default (the default `StatefulTransactionValidatorConfig` produces a `GAS_PRICE_TOO_LOW` error in tests), and `min_gas_price_percentage` is non-zero in production. The condition is therefore triggered on every block where gas usage deviates from the target.

### Recommendation

Replace the use of `previous_block_l2_gas_price` with the computed next block's L2 gas price. The next L2 gas price is already calculated by `calculate_next_l2_gas_price_for_fin` in the consensus orchestrator and stored in the block header's `next_l2_gas_price` field (visible in the cende blob). The gateway should read this value from the block header rather than using the current block's `l2_gas_price`. The TODO comment in the code already identifies this fix:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [7](#0-6) 

### Proof of Concept

1. Observe that the current committed block N has `l2_gas_price = P` and was filled to 75% of the gas target (high congestion).
2. Compute `P_next = calculate_next_base_gas_price(P, 0.75 * gas_target, gas_target, min)`. From the fee market snapshot tests, `P_next ≈ P * 1.01` (roughly 1% higher).
3. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P` (exactly the previous block price, which satisfies `threshold_pct = 100`).
4. The gateway calls `validate_tx_l2_gas_price_within_threshold` with `previous_block_l2_gas_price = P` and admits the transaction.
5. The batcher builds block N+1 with `l2_gas_price = P_next ≈ 1.01 * P`.
6. The blockifier's `check_fee_bounds` compares `max_price_per_unit = P` against `actual_gas_price = P_next > P` and returns `ResourceBoundsError::MaxGasPriceTooLow`, reverting the transaction.

The transaction passed gateway admission but was guaranteed to fail at execution — the gateway used the wrong oracle price, directly analogous to the Uniswap oracle using a stale/mock price instead of the real computed value.

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-100)
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
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/test.rs (L22-61)
```rust
#[rstest]
#[case::high_congestion(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 3 / 4),
    VERSIONED_CONSTANTS.max_block_size / 2,
    GasPrice(30312500000),
)]
#[case::low_congestion(
    VERSIONED_CONSTANTS.max_block_size / 4,
    VERSIONED_CONSTANTS.max_block_size / 2,
    GasPrice(29687500000),
)]
#[case::stable(
    VERSIONED_CONSTANTS.max_block_size / 2,
    VERSIONED_CONSTANTS.max_block_size / 2,
    INIT_PRICE
)]
#[case::high_congestion_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 9 / 10),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4 / 5), // Gas target 80%
    GasPrice(30078125000)
)]
#[case::low_congestion_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 / 4),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4 / 5), // Gas target 80%
    GasPrice(29570312500)
)]
#[case::stable_80(
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4/5),
    GasAmount(VERSIONED_CONSTANTS.max_block_size.0 * 4/5), // Gas target 80%
    INIT_PRICE
)]
fn price_calculation_snapshot(
    #[case] gas_used: GasAmount,
    #[case] gas_target: GasAmount,
    #[case] expected: GasPrice,
) {
    let min_gas_price = VERSIONED_CONSTANTS.min_gas_price;
    let actual = calculate_next_base_gas_price(INIT_PRICE, gas_used, gas_target, min_gas_price);
    assert_eq!(actual, expected);
}
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L60-67)
```rust
#[async_trait]
impl GatewayFixedBlockStateReader for GatewayFixedBlockSyncStateClient {
    async fn get_block_info(&self) -> StarknetResult<BlockInfo> {
        self.block_info_cache
            .get_or_try_init(|| self.get_block_info_from_sync_client())
            .await
            .cloned()
    }
```
