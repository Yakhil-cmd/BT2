### Title
Gateway Stateful Admission Validates L2 Gas Price Against Stale Previous-Block Price Instead of Next-Block Price - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful admission check (`validate_resource_bounds`) compares a transaction's `max_l2_gas_price` against the **previous block's** L2 gas price. However, the transaction will be executed in the **next block**, whose L2 gas price is computed by the EIP-1559 fee market (`calculate_next_l2_gas_price_for_fin`). When the network is congested and the next block's price rises above the previous block's price, the gateway admits transactions that the batcher's blockifier will reject during execution. The code itself acknowledges the defect with a TODO: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Finding Description

**Root cause — wrong reference price in `validate_resource_bounds`:** [1](#0-0) 

The function reads `previous_block_l2_gas_price` from `gateway_fixed_block_state_reader.get_block_info()` — the last committed block — and passes it to `validate_tx_l2_gas_price_within_threshold`. The threshold is `min_gas_price_percentage% × previous_block_l2_gas_price` (default 100 %). [2](#0-1) 

**The blockifier entry-point validation in the gateway also uses the stale price:**

`run_validate_entry_point` increments only the block number, leaving gas prices unchanged: [3](#0-2) 

So the blockifier validation inside the gateway also runs against `P_prev`, not `P_next`. It will not catch the discrepancy.

**The batcher executes against the EIP-1559-adjusted next-block price:**

The orchestrator computes the next block's L2 gas price via `calculate_next_l2_gas_price_for_fin`, which applies EIP-1559 mechanics: [4](#0-3) 

When the block is full (high congestion), `P_next > P_prev`. The batcher's blockifier then runs `check_fee_bounds` against `P_next`: [5](#0-4) 

**The gap:** any transaction with `P_prev ≤ max_l2_gas_price < P_next` passes the gateway but is rejected by the batcher.

**Reverse direction — valid transactions rejected:** When the network is under-congested and `P_next < P_prev`, a transaction with `P_next ≤ max_l2_gas_price < P_prev` is rejected by the gateway even though it would succeed in the next block.

**Only `AllResources` (V3) transactions are checked; `L1Gas` (legacy) transactions bypass the check entirely:** [6](#0-5) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions or rejects valid transactions before sequencing.**

1. **Accepts invalid transactions:** Under congestion (`P_next > P_prev`), transactions with `max_l2_gas_price = P_prev` pass the gateway, enter the mempool, and are later rejected by the batcher's `check_fee_bounds`. The sequencer wastes CPU, memory, and network resources on transactions that cannot be included. An attacker can flood the mempool with such transactions at zero cost (no fee is charged for pre-validation failures).

2. **Rejects valid transactions:** Under low congestion (`P_next < P_prev`), transactions with `P_next ≤ max_l2_gas_price < P_prev` are incorrectly rejected at the gateway even though they would succeed in the next block. This is a denial-of-service against legitimate users.

---

### Likelihood Explanation

**Likelihood: Low** (matching the external report's "Low" likelihood).

The EIP-1559 fee market adjusts the L2 gas price by at most `1/gas_price_max_change_denominator` per block. A single block's price change is small. However, the discrepancy is structural and permanent until the TODO is resolved. Under sustained congestion (many consecutive full blocks), the gap between `P_prev` and `P_next` accumulates, making the window of affected transactions wider. The condition is unprivileged — any user can submit a transaction at exactly `P_prev`.

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` with the computed next-block L2 gas price. The next-block price is already available via `calculate_next_l2_gas_price_for_fin` (used by the orchestrator) or can be read from `block_header_without_hash.next_l2_gas_price` once it is stored in the synced block header. The same corrected price should be passed into the `BlockContext` inside `run_validate_entry_point` so that the blockifier entry-point validation is consistent with the batcher's execution context. [7](#0-6) 

---

### Proof of Concept

```
Setup
-----
Previous block L2 gas price:  P_prev = 100 FRI/gas
min_gas_price_percentage:      100  (default)
EIP-1559 next-block price:     P_next = 110 FRI/gas  (block was 75 % full)

Step 1 — Attacker submits invoke V3 with max_l2_gas_price = 100 FRI/gas.

Step 2 — Gateway stateful validation:
  validate_tx_l2_gas_price_within_threshold:
    threshold = 100% × 100 = 100
    tx_l2_gas_price (100) >= threshold (100)  → PASS
  Transaction admitted to mempool.

Step 3 — Batcher builds next block with l2_gas_price = 110 FRI/gas.
  perform_pre_validation_stage → check_fee_bounds:
    resource_bounds.max_price_per_unit (100) < actual_gas_price (110)
    → ResourceBoundsError::MaxGasPriceTooLow  → REJECT

Step 4 — Transaction is dropped; sequencer consumed validation resources for nothing.
         Repeat at scale for a resource-exhaustion attack on the mempool/batcher pipeline.
```

The exact corrupted value is `previous_block_l2_gas_price` used as the admission threshold in `validate_tx_l2_gas_price_within_threshold` at line 370, where `next_block_l2_gas_price` is required. [8](#0-7)

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

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L55-77)
```rust
pub fn calculate_next_l2_gas_price_for_fin(
    current_l2_gas_price: GasPrice,
    height: BlockNumber,
    l2_gas_used: GasAmount,
    override_l2_gas_price_fri: Option<u128>,
    min_l2_gas_price_per_height: &[PricePerHeight],
    fee_actual: Option<GasPrice>,
) -> GasPrice {
    if let Some(override_value) = override_l2_gas_price_fri {
        info!(
            "L2 gas price ({}) is not updated, remains on override value of {override_value} fri",
            current_l2_gas_price.0
        );
        return GasPrice(override_value);
    }
    let gas_target = VersionedConstants::latest_constants().gas_target;
    let config_min = get_min_gas_price_for_height(height, min_l2_gas_price_per_height);
    let effective_min = match fee_actual {
        Some(fa) => GasPrice(max(config_min.0, fa.0)),
        None => config_min,
    };
    calculate_next_base_gas_price(current_l2_gas_price, l2_gas_used, gas_target, effective_min)
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
