### Title
Gateway L2 Gas Price Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Admitting Transactions That Fail Batcher Pre-Validation — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check and its embedded blockifier validation both read `block_N.l2_gas_price` (the price that was used *inside* the already-committed block N) as the reference price for the next block. The batcher, however, executes transactions in block N+1 using `block_N.next_l2_gas_price` — the EIP-1559-adjusted price computed from block N's gas consumption. When block N is above the gas target, `next_l2_gas_price > l2_gas_price`, so any V3 transaction whose `max_price_per_unit` for L2 gas falls in the gap `[l2_gas_price, next_l2_gas_price)` passes every gateway check but is rejected by the batcher's `check_fee_bounds` during pre-validation. The developer left an explicit TODO acknowledging the wrong field is being read.

---

### Finding Description

**Step 1 — Gateway reads the wrong price field.**

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` constructs a `BlockInfo` by copying `block_header.l2_gas_price` into `strk_gas_prices.l2_gas_price`: [1](#0-0) 

The block header also carries `block_header.next_l2_gas_price` — the EIP-1559 price for the *next* block — but this field is never read here.

**Step 2 — Gateway admission check uses that stale price.**

`validate_resource_bounds` fetches the `BlockInfo` built above and compares the transaction's `max_price_per_unit` against it. The TODO comment in the source code explicitly flags the wrong field: [2](#0-1) 

With the default `min_gas_price_percentage = 100`, the effective check is:

```
tx.l2_gas.max_price_per_unit  >=  block_N.l2_gas_price
``` [3](#0-2) 

**Step 3 — Gateway blockifier validation uses the same stale price.**

`run_validate_entry_point` also calls `get_block_info()`, increments the block number to N+1, but keeps the same (stale) gas prices: [4](#0-3) 

So `check_fee_bounds` inside the gateway's blockifier run also passes for any `tx.max_price >= block_N.l2_gas_price`.

**Step 4 — Batcher executes with the fresh `next_l2_gas_price`.**

After each decided block the consensus orchestrator calls `update_l2_gas_price`, which applies the EIP-1559 formula to produce `block_N.next_l2_gas_price`: [5](#0-4) 

This updated `self.l2_gas_price` is what the orchestrator stores in the block header as `next_l2_gas_price` and what it passes to the batcher as the L2 gas price for block N+1: [6](#0-5) 

When the batcher executes a transaction in block N+1, `check_fee_bounds` compares against this fresh price: [7](#0-6) [8](#0-7) 

**Step 5 — EIP-1559 price increase magnitude.**

`calculate_next_base_gas_price` increases the price proportionally to how far gas usage exceeds the target: [9](#0-8) 

With a full block (`gas_used = max_block_size`) and `gas_price_max_change_denominator = 8`, the price rises by up to 12.5 % per block. The gap between `l2_gas_price` and `next_l2_gas_price` is therefore not negligible.

---

### Impact Explanation

Any V3 (`AllResources`) transaction whose `l2_gas.max_price_per_unit` satisfies:

```
block_N.l2_gas_price  <=  max_price  <  block_N.next_l2_gas_price
```

will:
1. Pass `validate_resource_bounds` (gateway admission) — **admitted to mempool**
2. Pass the gateway's embedded blockifier validation — **no rejection at gateway**
3. Fail `check_fee_bounds` inside `perform_pre_validation_stage` in the batcher — **dropped from block without fee charge**

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

The mempool holds and propagates these transactions, consuming bandwidth and memory. An attacker who observes the current block's gas usage can reliably craft transactions that always pass the gateway but always fail the batcher, enabling sustained mempool pollution without paying fees.

---

### Likelihood Explanation

- Trigger condition: block N must be above the gas target (busy). On a live network under load this is the common case.
- No special privilege is required; any user can submit a V3 transaction.
- The attacker only needs to set `max_price_per_unit` to exactly `block_N.l2_gas_price`, which is publicly readable from the last committed block header.
- The TODO comment confirms the developers are aware the wrong field is used, meaning no compensating guard has been added.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace `block_header.l2_gas_price` with `block_header.next_l2_gas_price` when populating `strk_gas_prices.l2_gas_price` (and the corresponding WEI field). This makes both the admission check and the gateway's blockifier simulation use the same price the batcher will enforce. [10](#0-9) 

The same fix must be applied to `run_validate_entry_point`, which builds its `block_context` from the same `get_block_info()` call and therefore also simulates block N+1 with block N's (stale) gas prices. [4](#0-3) 

---

### Proof of Concept

1. Observe the latest committed block N. Read `block_N.l2_gas_price` (e.g. `P`) and `block_N.l2_gas_consumed` (e.g. `G`).
2. Compute `next_price = calculate_next_base_gas_price(P, G, gas_target, min_price)`. If `G > gas_target`, then `next_price > P`.
3. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P` (equal to the current block price, strictly below the next block price).
4. The gateway's `validate_resource_bounds` checks `P >= 100% * P` → **passes**.
5. The gateway's blockifier validation runs `check_fee_bounds` with a `BlockContext` whose `l2_gas_price = P` → **passes**.
6. The transaction enters the mempool.
7. When the batcher builds block N+1 with `l2_gas_price = next_price > P`, `check_fee_bounds` checks `P >= next_price` → **fails** with `MaxGasPriceTooLow`.
8. The transaction is dropped from the block without charging fees. Repeat from step 3 indefinitely. [11](#0-10) [12](#0-11)

### Citations

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L40-57)
```rust
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_wei.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_wei.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_wei.try_into()?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
            },
            use_kzg_da: block_header.l1_da_mode.is_use_kzg_da(),
            starknet_version: block_header.starknet_version,
        };

        Ok(block_info)
    }
```

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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-406)
```rust
        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L496-500)
```rust
    fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
        self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
        let gas_price_u64 = u64::try_from(self.l2_gas_price.0).unwrap_or(u64::MAX);
        CONSENSUS_L2_GAS_PRICE.set_lossy(gas_price_u64);
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L418-424)
```rust
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-448)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L117-139)
```rust
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
```
