### Title
Gateway validates L2 gas price against previous block's `l2_gas_price` instead of `next_l2_gas_price`, causing valid transactions to be rejected or under-priced transactions to be admitted - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads `gas_prices.strk_gas_prices.l2_gas_price` from the previous block's `BlockInfo` to threshold-check incoming V3 transactions' `max_price_per_unit`. The correct reference price is `BlockHeaderWithoutHash::next_l2_gas_price`, which is the EIP-1559-adjusted price that will actually govern the next block. Because the two values diverge every block, the gateway either rejects valid transactions (when the price fell) or admits transactions whose stated price is below the real next-block floor (when the price rose). The code itself carries a `TODO` acknowledging the wrong field is used.

### Finding Description

`validate_resource_bounds` is called for every incoming `AllResources` V3 transaction during stateful gateway validation:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 223-243
async fn validate_resource_bounds(...) {
    if self.config.validate_resource_bounds {
        // TODO(Arni): getnext_l2_gas_price from the block header.
        let previous_block_l2_gas_price = self
            .gateway_fixed_block_state_reader
            .get_block_info()
            .await?
            .gas_prices
            .strk_gas_prices
            .l2_gas_price;          // ← price used IN the previous block
        self.validate_tx_l2_gas_price_within_threshold(
            executable_tx.resource_bounds(),
            previous_block_l2_gas_price,
        )?;
    }
}
``` [1](#0-0) 

The threshold is then computed as:

```rust
// lines 367-383
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...) }
``` [2](#0-1) 

The EIP-1559 fee market computes a **different** price for the next block and stores it as `next_l2_gas_price` in `BlockHeaderWithoutHash`:

```rust
// crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs  lines 399-412
let block_header_without_hash = BlockHeaderWithoutHash {
    l2_gas_price,                          // price used in THIS block
    next_l2_gas_price: self.l2_gas_price,  // price for the NEXT block
    ...
};
``` [3](#0-2) 

`next_l2_gas_price` is derived by `calculate_next_base_gas_price` / `calculate_next_l2_gas_price_for_fin`, which adjusts the price up or down based on gas usage relative to the target: [4](#0-3) 

The gateway's `get_block_info()` returns `BlockInfo`, which exposes only `gas_prices.strk_gas_prices.l2_gas_price` (the price used in the committed block). `next_l2_gas_price` is stored only in `BlockHeaderWithoutHash` and is not surfaced through the `GatewayFixedBlockStateReader` interface, so the gateway has no path to the correct value.

### Impact Explanation

**Scenario A – price fell (previous block lightly used):**  
`next_l2_gas_price < l2_gas_price`. The gateway threshold is computed from the higher `l2_gas_price`, so it is too strict. A user who correctly sets `max_price_per_unit ≥ next_l2_gas_price × min_gas_price_percentage / 100` has their transaction rejected with `GAS_PRICE_TOO_LOW` even though it would be accepted and executed correctly by the batcher. This is a gateway admission error that rejects valid transactions.

**Scenario B – price rose (previous block heavily used):**  
`next_l2_gas_price > l2_gas_price`. The threshold is too lenient. Transactions with `max_price_per_unit` between the two thresholds pass the gateway but will be reverted by the blockifier's `check_fee_bounds` at execution time, wasting mempool capacity and causing user-visible failures.

Both scenarios match the Derby pattern: a cached rate value (`l2_gas_price`) is used in place of the current effective rate (`next_l2_gas_price`), producing wrong admission decisions.

### Likelihood Explanation

The EIP-1559 mechanism adjusts the L2 gas price every block. Any block with gas usage that differs from the target causes `next_l2_gas_price ≠ l2_gas_price`. This is the normal operating condition, not an edge case. Any user submitting a V3 (`AllResources`) transaction when `validate_resource_bounds = true` is affected. No special privileges or adversarial setup are required.

### Recommendation

Change `validate_resource_bounds` to read `next_l2_gas_price` from `BlockHeaderWithoutHash` rather than `l2_gas_price` from `BlockInfo`. This requires extending `GatewayFixedBlockStateReader` (or a companion trait) to expose `next_l2_gas_price`, which the TODO comment already anticipates:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
```

The fix aligns the gateway's admission check with the price that the batcher will actually enforce, eliminating both false rejections and false admissions.

### Proof of Concept

1. Deploy a sequencer with `validate_resource_bounds = true` and `min_gas_price_percentage = 50`.
2. Produce a block with gas usage **below** the EIP-1559 target so that `next_l2_gas_price < l2_gas_price` (e.g., an empty block).
3. Submit a V3 `invoke` transaction with `l2_gas.max_price_per_unit = next_l2_gas_price × 0.6` (above the correct threshold but below the stale threshold).
4. Observe: the gateway rejects the transaction with `GAS_PRICE_TOO_LOW` even though the batcher would have accepted and executed it at the correct next-block price.

The relevant code path is:

`Gateway::add_tx` → `StatefulTransactionValidator::extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `validate_state_preconditions` → `validate_resource_bounds` → `validate_tx_l2_gas_price_within_threshold` [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-221)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-391)
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-412)
```rust
        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
            timestamp: BlockTimestamp(init.timestamp),
            l1_da_mode: init.l1_da_mode,
            fee_proposal_fri: init.fee_proposal_fri,
            // TODO(guy.f): Figure out where/if to get the values below from and fill them.
            ..Default::default()
        };
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
