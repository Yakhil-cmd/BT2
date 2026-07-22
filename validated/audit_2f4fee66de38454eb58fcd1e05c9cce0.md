### Title
`StatelessTransactionValidatorConfig::min_gas_price` Diverges from `VersionedConstants::min_gas_price`, Causing Gateway Admission Inconsistency - (`crates/apollo_gateway_config/src/config.rs`)

### Summary

The `StatelessTransactionValidatorConfig` holds a static `min_gas_price` field that is set at node startup and never refreshed. The authoritative minimum L2 gas price floor is `VersionedConstants::min_gas_price` (the orchestrator versioned constants), which drives the EIP-1559 fee market and enforces the block gas price floor. These two values are independent and can diverge across protocol upgrades. The code itself acknowledges this with an open TODO. When they diverge, the gateway either rejects transactions that the blockifier would accept, or admits transactions that the blockifier will reject.

### Finding Description

`StatelessTransactionValidatorConfig` contains:

```rust
// TODO(AlonH): Remove the `min_gas_price` field from this struct and use the one from the
// versioned constants.
pub min_gas_price: u128,
``` [1](#0-0) 

The stateless validator enforces this static value as a hard gate on every incoming transaction:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
``` [2](#0-1) 

The authoritative source is `apollo_versioned_constants::VersionedConstants::min_gas_price`, which the fee market uses as the EIP-1559 price floor:

```rust
let fallback_min_gas_price = VersionedConstants::latest_constants().min_gas_price;
``` [3](#0-2) 

The versioned constants already show this value has changed across protocol versions:
- `orchestrator_versioned_constants_0_14_0.json`: `"min_gas_price": "0xb2d05e00"` = **3,000,000,000 fri** (3 Gwei)
- `orchestrator_versioned_constants_0_14_1.json` through `0_14_4.json`: `"min_gas_price": "0x1dcd65000"` = **8,000,000,000 fri** (8 Gwei) [4](#0-3) [5](#0-4) 

The static config default is hardcoded to 8 Gwei:

```rust
min_gas_price: 8_000_000_000,
``` [6](#0-5) 

These two values are set independently and there is no mechanism to synchronize them. The fee market guarantees the block L2 gas price is always `>= VersionedConstants::min_gas_price`:

```rust
GasPrice(max(adjusted_price, min_gas_price.0))
``` [7](#0-6) 

The blockifier's `check_fee_bounds` then rejects any transaction whose `max_price_per_unit` is below the block's actual gas price:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [8](#0-7) 

**Divergence scenario A — static config too high (`static_config.min_gas_price > VersionedConstants::min_gas_price`):**

If a future protocol upgrade lowers `VersionedConstants::min_gas_price` (e.g., back to 3 Gwei) while the static config remains at 8 Gwei, the stateless validator rejects every transaction with `max_price_per_unit` in `[3 Gwei, 8 Gwei)`. These transactions are fully valid from the blockifier's perspective (the block gas price floor is 3 Gwei), so the gateway incorrectly denies admission to valid transactions.

**Divergence scenario B — static config too low (`static_config.min_gas_price < VersionedConstants::min_gas_price`):**

If the protocol upgrades `VersionedConstants::min_gas_price` upward (as happened from v0.14.0 → v0.14.1) while the static config is not updated, the stateless validator admits transactions with `max_price_per_unit` in `[static_config.min_gas_price, VersionedConstants::min_gas_price)`. The fee market floor guarantees the block gas price is `>= VersionedConstants::min_gas_price`, so these transactions will fail `check_fee_bounds` at blockifier execution time. The stateful validator's threshold check (`validate_tx_l2_gas_price_within_threshold`) uses the *previous* block's gas price and only catches this when `min_gas_price_percentage = 100` and the previous block was already at the new minimum — a condition that is not guaranteed during the transition period. [9](#0-8) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions or rejects valid transactions before sequencing.**

- Scenario A: valid transactions (acceptable to the blockifier) are permanently rejected at the stateless gate, constituting a denial-of-service for users willing to pay the protocol-minimum gas price.
- Scenario B: transactions that will unconditionally fail at blockifier execution are admitted into the mempool, consuming mempool slots and batcher execution resources.

Both outcomes break the invariant that the gateway's admission decision is consistent with the blockifier's execution decision.

### Likelihood Explanation

The divergence is latent in the current codebase (acknowledged by the TODO comment) and is triggered by any protocol upgrade that changes `VersionedConstants::min_gas_price` without a corresponding update to the deployed `StatelessTransactionValidatorConfig`. The versioned constants history already shows one such change (3 Gwei → 8 Gwei between v0.14.0 and v0.14.1). Future upgrades are likely to change this value again.

### Recommendation

Remove `min_gas_price` from `StatelessTransactionValidatorConfig` and read the value directly from `VersionedConstants::latest_constants().min_gas_price` inside `StatelessTransactionValidator::validate_resource_bounds`, as the TODO comment already prescribes. This eliminates the independent copy and ensures the gateway always enforces the same floor as the fee market.

### Proof of Concept

**Scenario A (valid transaction rejected):**

1. Protocol upgrades to a version where `VersionedConstants::min_gas_price = 3_000_000_000` (3 Gwei).
2. Operator does not update the gateway config; `StatelessTransactionValidatorConfig::min_gas_price` remains `8_000_000_000`.
3. User submits an invoke transaction with `l2_gas.max_price_per_unit = 5_000_000_000` (5 Gwei).
4. `StatelessTransactionValidator::validate_resource_bounds` evaluates `5_000_000_000 < 8_000_000_000` → returns `MaxGasPriceTooLow` error; transaction is rejected.
5. The blockifier would have accepted this transaction: the block gas price floor is 3 Gwei, and 5 Gwei ≥ 3 Gwei.

**Scenario B (invalid transaction admitted):**

1. Protocol upgrades to a version where `VersionedConstants::min_gas_price = 16_000_000_000` (16 Gwei).
2. Operator does not update the gateway config; `StatelessTransactionValidatorConfig::min_gas_price` remains `8_000_000_000`.
3. User submits an invoke transaction with `l2_gas.max_price_per_unit = 10_000_000_000` (10 Gwei).
4. `StatelessTransactionValidator::validate_resource_bounds` evaluates `10_000_000_000 >= 8_000_000_000` → passes.
5. During the transition period, the previous block's gas price may still be above 10 Gwei (due to congestion), so `validate_tx_l2_gas_price_within_threshold` also passes.
6. Transaction enters the mempool and reaches the batcher.
7. The fee market floor is 16 Gwei; the block gas price is `>= 16_000_000_000`. Blockifier `check_fee_bounds` evaluates `10_000_000_000 < 16_000_000_000` → `MaxGasPriceTooLow`; transaction fails execution.

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L170-172)
```rust
    // TODO(AlonH): Remove the `min_gas_price` field from this struct and use the one from the
    // versioned constants.
    pub min_gas_price: u128,
```

**File:** crates/apollo_gateway_config/src/config.rs (L192-192)
```rust
            min_gas_price: 8_000_000_000,
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L71-76)
```rust
        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L45-51)
```rust
    let fallback_min_gas_price = VersionedConstants::latest_constants().min_gas_price;
    min_l2_gas_price_per_height
        .iter()
        .rev()
        .find(|e| e.height <= height.0)
        .map(|e| GasPrice(e.price))
        .unwrap_or(fallback_min_gas_price)
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L139-139)
```rust
    GasPrice(max(adjusted_price, min_gas_price.0))
```

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_0.json (L1-9)
```json
{
    "fee_proposal_margin_ppt": 2,
    "fee_proposal_window_size": 10,
    "gas_price_max_change_denominator": 48,
    "gas_target": 3200000000,
    "max_block_size": 4000000000,
    "min_gas_price": "0xb2d05e00",
    "l1_gas_price_margin_percent": 10
}
```

**File:** crates/apollo_versioned_constants/resources/orchestrator_versioned_constants_0_14_1.json (L1-9)
```json
{
    "fee_proposal_margin_ppt": 2,
    "fee_proposal_window_size": 10,
    "gas_price_max_change_denominator": 48,
    "gas_target": 4000000000,
    "max_block_size": 5000000000,
    "min_gas_price": "0x1dcd65000",
    "l1_gas_price_margin_percent": 10
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
