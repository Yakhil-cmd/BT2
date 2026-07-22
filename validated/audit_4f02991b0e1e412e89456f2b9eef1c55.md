### Title
Gateway Stateful Validator Admits Transactions Using Stale Previous-Block L2 Gas Price While Batcher Enforces Current-Block Price — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `validate_resource_bounds` and the blockifier validation it invokes both use the **previous (last-committed) block's** L2 gas price as the reference for admission. The batcher, however, builds each new block with a **freshly computed current-block** L2 gas price (SNIP-35 EIP-1559 formula). When the current-block price rises above the previous-block price, transactions whose `max_price_per_unit` falls in the gap `[previous_block_price, current_block_price)` pass every gateway check and enter the mempool, but are then rejected by `check_fee_bounds` during block building. Conversely, when the price falls, transactions whose `max_price_per_unit` is above the current-block price but below the previous-block threshold are incorrectly rejected at the gateway even though they would succeed during sequencing.

---

### Finding Description

**Step 1 — Gateway soft check (stale price)**

`StatefulTransactionValidator::validate_resource_bounds` reads the L2 gas price from `gateway_fixed_block_state_reader.get_block_info()`, which is pinned to the latest *committed* block (`latest_block_number` at the moment the validator was instantiated). The developer-acknowledged TODO on line 229 confirms this is wrong:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
``` [1](#0-0) 

The threshold applied is `min_gas_price_percentage * previous_block_price / 100`. A transaction with `max_price_per_unit = previous_block_price` passes this check.

**Step 2 — Gateway blockifier hard check (same stale price)**

`run_validate_entry_point` builds a `BlockContext` from the same `gateway_fixed_block_state_reader` block info, only incrementing the block number:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [2](#0-1) 

The gas prices in this `BlockContext` are still the previous block's prices. `perform_pre_validation_stage` → `check_fee_bounds` therefore checks `max_price_per_unit >= previous_block_price`, which passes for the same transaction. [3](#0-2) [4](#0-3) 

**Step 3 — Batcher uses the current-block price (different value)**

The consensus orchestrator computes a fresh L2 gas price each block via the SNIP-35 formula and passes it to the batcher inside `ProposeBlockInput.block_info`. The batcher immediately propagates this price to the mempool:

```rust
mempool_client
    .update_gas_price(
        propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
    )
    .await
``` [5](#0-4) 

When the blockifier executes the transaction inside the block builder, it uses this current-block `BlockContext`. `check_fee_bounds` now checks `max_price_per_unit >= current_block_price`. If `current_block_price > previous_block_price`, the transaction that passed the gateway fails here with `ResourceBoundsError::MaxGasPriceTooLow`. [6](#0-5) 

**The invariant broken:** every transaction admitted to the mempool by the gateway must satisfy the fee bounds that will be enforced during block building. Because the gateway uses a stale price and the batcher uses a live price, this invariant is violated whenever the two prices diverge.

---

### Impact Explanation

- **Rising gas prices:** Transactions with `previous_block_price ≤ max_price_per_unit < current_block_price` are admitted to the mempool but fail `check_fee_bounds` during block building. They consume mempool slots, waste batcher CPU, and are never sequenced. An unprivileged attacker can deliberately submit many such transactions to exhaust mempool capacity.
- **Falling gas prices:** Transactions with `current_block_price ≤ max_price_per_unit < previous_block_price * min_gas_price_percentage / 100` are rejected by the gateway even though they would succeed during sequencing. Legitimate users are incorrectly denied admission.

Both directions match **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The L2 gas price is updated every block by the SNIP-35 EIP-1559 formula (approximately ±0.3 % per block under normal load, larger swings during congestion spikes). Because the gateway validator is instantiated once per transaction from the latest committed block, and block production is continuous, there is always a non-zero window between the price used for admission and the price used for execution. The window widens during periods of rapid gas-price movement.

---

### Recommendation

Replace the stale `previous_block_l2_gas_price` in `validate_resource_bounds` with the **next block's** L2 gas price — the same value the orchestrator will pass to the batcher. The TODO comment on line 229 already identifies this fix. Until the next-block price is available at gateway time, the gateway should at minimum use the current block's price (from the block being built) rather than the last committed block's price. The blockifier validation in `run_validate_entry_point` should likewise be constructed with the same gas prices that the batcher will use, so that gateway admission and block-building enforcement are always consistent.

---

### Proof of Concept

Assume `min_gas_price_percentage = 100`.

| Step | Actor | L2 gas price used | `max_price_per_unit` | Result |
|---|---|---|---|---|
| Block N committed | — | P = 100 | — | — |
| Gateway validates tx | Gateway | P = 100 (stale) | 100 | **PASS** (100 ≥ 100) |
| Block N+1 built | Batcher | P′ = 101 (SNIP-35 tick) | 100 | **FAIL** (100 < 101) |

The transaction is accepted into the mempool and propagated to peers, but is silently dropped during block building. Repeating this at scale with many transactions floods the mempool with permanently unsequenceable entries.

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-458)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
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
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```

**File:** crates/apollo_batcher/src/batcher.rs (L371-383)
```rust
        info!(
            "Updating gas price for block {}, round {} in Mempool client",
            block_number, propose_block_input.proposal_round
        );
        mempool_client
            .update_gas_price(
                propose_block_input.block_info.gas_prices.strk_gas_prices.l2_gas_price.get(),
            )
            .await
            .map_err(|err| {
                error!("Failed to update gas price in mempool: {}", err);
                BatcherError::InternalError
            })?;
```
