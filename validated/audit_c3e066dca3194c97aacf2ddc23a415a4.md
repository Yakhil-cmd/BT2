### Title
Gateway Stateful Validator Uses Stale Previous-Block L2 Gas Price for Resource Bounds Admission, Causing Mempool Admission/Rejection Mismatch — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful admission check for L2 gas price compares the transaction's `max_price_per_unit` against the **previous committed block's** L2 gas price. The actual execution block built by the batcher uses the **next block's** L2 gas price, computed via the EIP-1559-style fee market. Because these two prices can diverge in either direction, the gateway systematically admits transactions that the batcher will reject, and rejects transactions the batcher would accept. The code itself carries an explicit TODO acknowledging the wrong value is being used.

---

### Finding Description

**Root cause — wrong reference price in `validate_resource_bounds`:** [1](#0-0) 

```rust
async fn validate_resource_bounds(...) {
    if self.config.validate_resource_bounds {
        // TODO(Arni): getnext_l2_gas_price from the block header.   ← acknowledged bug
        let previous_block_l2_gas_price = self
            .gateway_fixed_block_state_reader
            .get_block_info()
            .await?
            .gas_prices
            .strk_gas_prices
            .l2_gas_price;                          // ← PREVIOUS block price
        self.validate_tx_l2_gas_price_within_threshold(
            executable_tx.resource_bounds(),
            previous_block_l2_gas_price,            // ← used as threshold
        )?;
    }
}
```

The threshold is `(min_gas_price_percentage / 100) * previous_block_l2_gas_price`. With the production default of `min_gas_price_percentage = 100`, a transaction passes if `tx.l2_gas.max_price_per_unit >= previous_block_l2_gas_price`. [2](#0-1) 

**The execution block uses a different price:**

`run_validate_entry_point` also builds its `BlockContext` from the same previous-block info (only incrementing the block number, not the gas price): [3](#0-2) 

The batcher, however, computes the **next** block's L2 gas price via the EIP-1559 fee market (`calculate_next_l2_gas_price`) and uses that price in the block context for actual execution: [4](#0-3) [5](#0-4) 

The batcher's `check_fee_bounds` (called inside `perform_pre_validation_stage`) then compares the transaction's `max_price_per_unit` against the **next** block's L2 gas price: [6](#0-5) [7](#0-6) 

**The two diverging scenarios:**

| Condition | Gateway decision | Batcher decision | Outcome |
|---|---|---|---|
| `next_price > prev_price` (congested block) | **ADMIT** (tx.price ≥ prev_price) | **REJECT** (tx.price < next_price) | Tx stuck in mempool, never sequenced |
| `next_price < prev_price` (uncongested block) | **REJECT** (tx.price < prev_price) | **ACCEPT** (tx.price ≥ next_price) | Valid tx permanently blocked at gateway |

The production default config confirms this is live: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

**High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

- **Accepts-invalid path**: During any period of rising L2 gas demand (EIP-1559 price increase), every transaction priced at exactly `previous_block_l2_gas_price` passes gateway admission and enters the mempool, but will be rejected by the batcher's `check_fee_bounds` because the execution block's price is higher. These transactions occupy mempool slots indefinitely until evicted by nonce advancement or timeout.
- **Rejects-valid path**: During any period of falling L2 gas demand (price decrease), transactions priced at the correct next-block price are rejected at the gateway even though the batcher would accept them. Users are forced to overpay or retry.

Both paths are reachable by any unprivileged user submitting a standard `InvokeTransaction` with `ValidResourceBounds::AllResources`.

---

### Likelihood Explanation

The EIP-1559 fee market (`calculate_next_base_gas_price`) adjusts the L2 gas price every block based on actual gas consumption relative to the gas target. Any block that is not exactly at the gas target produces a price different from the previous block's price. This is the normal operating condition, making the mismatch a near-constant occurrence rather than an edge case.

---

### Recommendation

Replace `previous_block_l2_gas_price` in `validate_resource_bounds` with the **next block's** L2 gas price, which is already stored in the block header as `next_l2_gas_price` (as the TODO comment itself states). The `GatewayFixedBlockStateReader::get_block_info` should expose `next_l2_gas_price` from the block header, and `validate_resource_bounds` should use that value as the threshold reference. The same correction should be applied to the `BlockContext` constructed inside `run_validate_entry_point` so that the gateway's blockifier pre-validation uses the same gas price the batcher will use.

---

### Proof of Concept

1. Observe the previous committed block's L2 gas price `P_prev` (e.g., via `starknet_getBlockWithTxs`).
2. Submit an `InvokeTransaction` (v3, `AllResources`) with `l2_gas.max_price_per_unit = P_prev`.
3. The gateway's `validate_resource_bounds` passes: `P_prev >= 1.0 * P_prev`.
4. The gateway's blockifier pre-validation also passes (uses same `P_prev`).
5. The transaction is admitted to the mempool.
6. The batcher builds the next block. If gas consumption in the previous block exceeded the gas target, `calculate_next_base_gas_price` produces `P_next > P_prev`.
7. The batcher's `check_fee_bounds` rejects the transaction: `P_prev < P_next`.
8. The transaction is never included in any block despite having passed all gateway checks.

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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L425-441)
```rust
    /// Returns the next L2 gas price without mutating context. Used when building the fin and when
    /// updating at decision time.
    fn calculate_next_l2_gas_price(&self, height: BlockNumber, l2_gas_used: GasAmount) -> GasPrice {
        let fee_actual = compute_fee_actual(
            &self.fee_proposals_window,
            height,
            VersionedConstants::latest_constants().fee_proposal_window_size,
        );
        calculate_next_l2_gas_price_for_fin(
            self.l2_gas_price,
            height,
            l2_gas_used,
            self.config.dynamic_config.override_l2_gas_price_fri,
            &self.config.dynamic_config.min_l2_gas_price_per_height,
            fee_actual,
        )
    }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L54-77)
```rust
/// Compute the next L2 gas price (for the fin or for updating state). Respects override when set.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-425)
```rust
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
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

**File:** crates/apollo_node/resources/config_schema.json (L3112-3126)
```json
  "gateway_config.static_config.stateful_tx_validator_config.min_gas_price_percentage": {
    "description": "Minimum gas price as percentage of threshold to accept transactions.",
    "privacy": "Public",
    "value": 100
  },
  "gateway_config.static_config.stateful_tx_validator_config.reject_future_declare_txs": {
    "description": "If true, rejects declare transactions with future nonces.",
    "privacy": "Public",
    "value": true
  },
  "gateway_config.static_config.stateful_tx_validator_config.validate_resource_bounds": {
    "description": "If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas price of the previous block.",
    "pointer_target": "validate_resource_bounds",
    "privacy": "Public"
  },
```
