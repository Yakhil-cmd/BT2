### Title
Gateway `validate_resource_bounds` reads stale `l2_gas_price` instead of `next_l2_gas_price`, causing wrong admission decisions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful `validate_resource_bounds` computes its admission threshold from the **current block's** `l2_gas_price` field, but the block being built will execute at the **next block's** `next_l2_gas_price`. The code itself carries an open TODO acknowledging the wrong field is read. This produces a systematic mismatch: when the L2 gas price rises between blocks, the gateway admits transactions whose `max_price_per_unit` is below the actual execution price, so they are accepted into the mempool but rejected by the blockifier during block building. When the price falls, valid transactions are incorrectly rejected at the gateway.

---

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` fetches the reference price via `gateway_fixed_block_state_reader.get_block_info()`: [1](#0-0) 

The concrete implementation of that reader, `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, constructs `BlockInfo` by reading `block_header.l2_gas_price.price_in_fri`: [2](#0-1) 

That field is the L2 gas price **used inside block N** (the latest committed block). It is distinct from `block_header.next_l2_gas_price`, which is the L2 gas price that will govern block N+1 — the block actually being built. The consensus orchestrator writes both fields separately when committing a block: [3](#0-2) 

`l2_gas_price` is the price that was in effect for block N; `next_l2_gas_price: self.l2_gas_price` is the freshly computed price for block N+1. The gateway reads only the former.

The threshold check then computes:

```
threshold = min_gas_price_percentage% × block_N.l2_gas_price
```

and admits any transaction whose `l2_gas.max_price_per_unit ≥ threshold`: [4](#0-3) 

The blockifier's `check_fee_bounds`, executed during actual block building, compares the same field against the **block N+1** gas price (i.e., `next_l2_gas_price`): [5](#0-4) 

The two checks therefore operate on different reference prices. The developer acknowledged the correct field is missing with an explicit TODO: [6](#0-5) 

The factory that wires the reader always passes `latest_block_number` to `GatewayFixedBlockSyncStateClient`, so there is no code path that supplies `next_l2_gas_price` to the gateway validator: [7](#0-6) 

---

### Impact Explanation

**Case 1 — price rose (next > current):** The gateway threshold is computed from the lower, stale price. A transaction with `max_price_per_unit` in the range `[threshold, next_l2_gas_price)` passes gateway admission and enters the mempool, but `check_fee_bounds` in the blockifier rejects it with `MaxGasPriceTooLow` during block building. The transaction is silently dropped from the block; the user receives no fee refund and must resubmit.

**Case 2 — price fell (next < current):** The gateway threshold is computed from the higher, stale price. A transaction with `max_price_per_unit` in the range `[next_l2_gas_price, threshold)` is rejected at the gateway even though the blockifier would accept it. Valid transactions are denied entry.

Both cases match the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The L2 gas price is updated every block by `update_l2_gas_price` / `calculate_next_l2_gas_price` in the consensus orchestrator: [8](#0-7) 

Any block with non-zero L2 gas consumption produces a `next_l2_gas_price` that differs from the current block's `l2_gas_price`. This is the normal operating condition, not an edge case. The discrepancy is present on every transaction validated after a block whose gas usage caused a price change.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace the `l2_gas_price` field with `block_header.next_l2_gas_price`:

```rust
// Before (wrong):
l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,

// After (correct):
l2_gas_price: block_header.next_l2_gas_price.try_into()?,
```

This aligns the gateway's admission threshold with the price the blockifier will actually enforce during block building, resolving the TODO at line 229 of `stateful_transaction_validator.rs`.

---

### Proof of Concept

1. Block N is committed with `l2_gas_price = 100 FRI` and `next_l2_gas_price = 115 FRI` (gas usage was above target).
2. A user submits an `AllResources` invoke transaction with `l2_gas.max_price_per_unit = 108 FRI`.
3. Gateway reads `previous_block_l2_gas_price = 100 FRI` (from `block_header.l2_gas_price`).
4. With `min_gas_price_percentage = 100`, threshold = `100 FRI`; `108 ≥ 100` → **gateway admits the transaction**.
5. Transaction enters the mempool and is selected for block N+1.
6. Batcher builds block N+1 with `l2_gas_price = 115 FRI` (from `next_l2_gas_price`).
7. Blockifier `check_fee_bounds`: `108 < 115` → `MaxGasPriceTooLow` → **transaction rejected during block building**.
8. Transaction is dropped; user loses the opportunity cost and must resubmit with a higher price.

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L36-57)
```rust
        let block_info = BlockInfo {
            block_number: block_header.block_number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer.0,
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L496-499)
```rust
    fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
        self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
        let gas_price_u64 = u64::try_from(self.l2_gas_price.0).unwrap_or(u64::MAX);
        CONSENSUS_L2_GAS_PRICE.set_lossy(gas_price_u64);
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L418-448)
```rust
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
```

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L545-549)
```rust
        let gateway_fixed_block_sync_state_client = GatewayFixedBlockSyncStateClient::new(
            self.shared_state_sync_client.clone(),
            latest_block_number,
        );
        Ok((blockifier_state_reader.into(), gateway_fixed_block_sync_state_client.into()))
```
