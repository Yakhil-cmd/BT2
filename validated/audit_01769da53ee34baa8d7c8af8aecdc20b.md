### Title
Gateway L2 Gas Price Admission Check Uses Current Block Price Instead of `next_l2_gas_price` — (`crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs`)

---

### Summary

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates `BlockInfo.gas_prices.strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` (the price **of the just-committed block**) while silently discarding `block_header.next_l2_gas_price` (the EIP-1559-adjusted price **for the next block**). Every downstream gateway check — the stateful `validate_tx_l2_gas_price_within_threshold` and the blockifier `check_fee_bounds` inside `run_validate_entry_point` — therefore validates a transaction against the wrong price. The batcher builds the next block using `next_l2_gas_price`, so the two prices diverge whenever the network is not exactly at the gas target. The gateway admits transactions that will fail in the batcher, and rejects transactions that would succeed.

---

### Finding Description

**Wrong value selected in `get_block_info_from_sync_client`**

`BlockHeaderWithoutHash` carries two distinct L2 gas price fields:

```
l2_gas_price: GasPricePerToken   // price used in the block just committed
next_l2_gas_price: GasPrice      // EIP-1559 price for the *next* block
``` [1](#0-0) 

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` maps the block header to `BlockInfo` using `l2_gas_price` for both ETH and STRK vectors, and never reads `next_l2_gas_price`: [2](#0-1) 

**Propagation through gateway validation**

`validate_resource_bounds` reads `strk_gas_prices.l2_gas_price` from this `BlockInfo` and passes it as `previous_block_l2_gas_price` to `validate_tx_l2_gas_price_within_threshold`. The TODO comment in the code itself acknowledges the wrong field is being used: [3](#0-2) 

`run_validate_entry_point` also builds the blockifier `BlockContext` from the same `BlockInfo` (only `block_number` is incremented), so `check_fee_bounds` inside `perform_pre_validation_stage` also compares `resource_bounds.max_price_per_unit` against the wrong price: [4](#0-3) [5](#0-4) 

**Batcher uses `next_l2_gas_price`**

When a block is committed, `update_state_sync_with_new_block` writes `next_l2_gas_price: self.l2_gas_price` into the block header stored in state sync. When the consensus context syncs, it reads `block_header_without_hash.next_l2_gas_price` to initialize `self.l2_gas_price` for the next block: [6](#0-5) 

The batcher therefore executes transactions at `next_l2_gas_price`, not at `l2_gas_price`.

---

### Impact Explanation

The EIP-1559 formula adjusts the price by up to `price / gas_price_max_change_denominator` per block. When the network is busy (`l2_gas_used > gas_target`), `next_l2_gas_price > l2_gas_price`. A transaction with `max_price_per_unit` in the range `[l2_gas_price, next_l2_gas_price)` passes both gateway checks but fails `check_fee_bounds` in the batcher, causing it to revert with `InsufficientResourceBounds`. The gateway has admitted an invalid transaction.

When the network is idle, `next_l2_gas_price < l2_gas_price`. A transaction with `max_price_per_unit` in `[next_l2_gas_price, l2_gas_price)` is rejected by the gateway even though it would succeed in the batcher. The gateway has rejected a valid transaction.

Both directions are reachable by any unprivileged user submitting a V3 `AllResources` transaction. The `min_gas_price_percentage` config (default 100%) provides no buffer against this mismatch because it scales the wrong base price.

**Matched impact:** *High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

---

### Likelihood Explanation

The L2 gas price changes every block. Any block where `l2_gas_used ≠ gas_target` produces a `next_l2_gas_price` that differs from `l2_gas_price`. Under normal network load the divergence is small but non-zero; under sustained high or low load it compounds across blocks. The condition is continuously present in production and requires no special attacker capability — any wallet submitting a V3 transaction is affected.

---

### Recommendation

In `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client`, replace `block_header.l2_gas_price.price_in_fri` (and the WEI counterpart) with `block_header.next_l2_gas_price` when populating the `l2_gas_price` field of `BlockInfo`. Because `next_l2_gas_price` is a single `GasPrice` (not a `GasPricePerToken`), the WEI value must be derived via the same ETH/STRK conversion used elsewhere in the codebase. This is exactly what the existing TODO comment requests:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
``` [7](#0-6) 

---

### Proof of Concept

1. Suppose the latest committed block has `l2_gas_price = 10 Gwei` and `next_l2_gas_price = 11 Gwei` (network is busy; price rose ~10%).
2. A user submits a V3 invoke with `l2_gas.max_price_per_unit = 10.5 Gwei`.
3. Gateway `validate_resource_bounds` computes threshold = `100% × 10 Gwei = 10 Gwei`. Check passes (`10.5 ≥ 10`).
4. Gateway `run_validate_entry_point` builds `BlockContext` with `l2_gas_price = 10 Gwei`. Blockifier `check_fee_bounds` checks `10.5 ≥ 10`. Passes.
5. Transaction enters the mempool.
6. Batcher builds the next block with `l2_gas_price = 11 Gwei` (from `next_l2_gas_price`). Blockifier `check_fee_bounds` checks `10.5 ≥ 11`. **Fails** → `InsufficientResourceBounds` → transaction reverts.

The gateway admitted a transaction that the batcher cannot include without reverting, wasting mempool capacity and degrading user experience. The root cause is the wrong field selected at: [8](#0-7)

### Citations

**File:** crates/starknet_api/src/block.rs (L237-239)
```rust
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-425)
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
