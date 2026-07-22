### Title
Gateway Stateful Validator Uses Stale Previous-Block L2 Gas Price Instead of Next-Block Price for Resource Bounds Validation — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` reads the L2 gas price from the **previous** committed block and uses it to gate admission into the mempool. The transaction will actually be executed in the **next** block, whose L2 gas price is computed by the EIP-1559-style fee market and can be materially higher. Transactions whose `max_price_per_unit` sits between the previous-block price and the next-block price pass every gateway check and enter the mempool, then fail `check_fee_bounds` during batcher execution. The code itself carries an explicit acknowledgement of the wrong value: `// TODO(Arni): getnext_l2_gas_price from the block header.`

---

### Finding Description

**Stale price read in `validate_resource_bounds`**

`validate_resource_bounds` calls `get_block_info()`, which returns the latest *committed* block's `BlockInfo`, and extracts `strk_gas_prices.l2_gas_price` from it: [1](#0-0) 

The variable is named `previous_block_l2_gas_price` and the TODO comment on line 229 explicitly states the correct value should be `next_l2_gas_price` from the block header. That field exists in the on-chain block structure: [2](#0-1) 

but is never surfaced through `GatewayFixedBlockStateReader`: [3](#0-2) 

**Same stale price propagated into blockifier gateway validation**

`run_validate_entry_point` also calls `get_block_info()`, increments only the block number, and passes the resulting `BlockInfo` (still carrying the previous block's gas prices) to `BlockContext`: [4](#0-3) 

The blockifier's `check_fee_bounds` inside `StatefulValidator::validate` therefore also compares `tx.max_price_per_unit` against the previous block's L2 gas price, not the next block's price: [5](#0-4) 

**Divergence from actual batcher execution**

The batcher computes the next block's L2 gas price via the EIP-1559 fee market (`calculate_next_l2_gas_price_for_fin`) and uses that price when building the real `BlockContext` for execution: [6](#0-5) 

When the network is under load the next-block price is strictly greater than the previous-block price. The gateway's two checks both pass for a transaction whose `max_price_per_unit` equals the previous-block price, but `check_fee_bounds` in the batcher will reject it with `MaxGasPriceTooLow`.

---

### Impact Explanation

**Impact: High** — Mempool/gateway admission accepts transactions that are invalid at execution time.

Any transaction with `max_price_per_unit` in the range `[previous_block.l2_gas_price, next_block.l2_gas_price)` clears both gateway checks (`validate_resource_bounds` and the blockifier gateway validation in `run_validate_entry_point`) and is pushed into the mempool. When the batcher dequeues it and runs `perform_pre_validation_stage` → `check_fee_bounds` against the actual next-block price, the transaction fails with `InsufficientResourceBounds { MaxGasPriceTooLow }`. The mempool slot is consumed, the batcher wastes execution resources, and the user's transaction is silently dropped.

---

### Likelihood Explanation

**Likelihood: Medium** — The L2 gas price changes every block. During any period of rising demand the next-block price exceeds the previous-block price by the EIP-1559 adjustment factor. No special privileges are required; any user can submit a transaction with `max_price_per_unit` set to the current (previous-block) price and trigger the mismatch.

---

### Recommendation

1. Expose `next_l2_gas_price` through `GatewayFixedBlockStateReader` (it is already stored in `BlockHeaderWithoutHash`).
2. In `validate_resource_bounds`, replace the read of `strk_gas_prices.l2_gas_price` with `next_l2_gas_price` — resolving the acknowledged TODO on line 229.
3. In `run_validate_entry_point`, populate the `BlockContext`'s gas prices from `next_l2_gas_price` rather than from the previous block's `gas_prices` vector, so the gateway blockifier validation uses the same price the batcher will use.

---

### Proof of Concept

1. Read the latest committed block; note its `l2_gas_price` = P and `next_l2_gas_price` = P′ > P (any block during rising demand).
2. Craft an `InvokeTransaction` V3 with `AllResourceBounds` where `l2_gas.max_price_per_unit = P` (equal to the previous-block price, strictly below P′).
3. Submit via the gateway `add_tx` endpoint.
4. `StatelessTransactionValidator::validate_resource_bounds` passes: `P >= min_gas_price` (stateless floor).
5. `StatefulTransactionValidator::validate_resource_bounds` passes: `P >= min_gas_price_percentage/100 * P` (threshold check against the same stale price P).
6. `run_validate_entry_point` passes: the `BlockContext` is built with gas price P (previous block), so `check_fee_bounds` sees `max_price P >= actual_price P` — no error.
7. Transaction is pushed to the mempool.
8. Batcher dequeues the transaction and builds a `BlockContext` with the correct next-block price P′.
9. `perform_pre_validation_stage` → `check_fee_bounds` evaluates `max_price P < actual_price P′` → `InsufficientResourceBounds { MaxGasPriceTooLow }` — transaction fails and is discarded.

The gateway admitted a transaction that the execution engine rejects, satisfying the "admission accepts invalid transactions" criterion. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_starknet_client/src/reader/objects/block.rs (L296-299)
```rust
    pub fn next_l2_gas_price(&self) -> GasPrice {
        match self {
            Block::PostV0_13_1(block) => block.next_l2_gas_price,
        }
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L14-17)
```rust
pub trait GatewayFixedBlockStateReader: Send + Sync {
    async fn get_block_info(&self) -> StarknetResult<BlockInfo>;
    async fn get_nonce(&self, contract_address: ContractAddress) -> StarknetResult<Nonce>;
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
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
