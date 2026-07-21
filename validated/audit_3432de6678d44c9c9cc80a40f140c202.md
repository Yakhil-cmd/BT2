Now I have all the evidence needed. Let me verify the exact `FeeEstimation` output structure to confirm the l2_gas_price is included in the response.

### Title
Stale Pending Block Synthesizes `DeprecatedPendingBlock` With Zero `l2_gas_price`, Causing `estimate_fee`/`simulate_transactions` to Return Authoritative-Looking Wrong Fee — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`)

---

### Summary

When the in-memory pending block is stale (its `parent_block_hash` does not match the latest committed block hash), `read_pending_data` synthesizes a fallback `DeprecatedPendingBlock`. That type structurally has no `l2_gas_price` field, so `l2_gas_price()` always returns `GasPricePerToken::default()` (zero). `create_block_context` then substitutes `NonzeroGasPrice::MIN` (= 1) for the zero value. Any call to `starknet_estimateFee`, `starknet_simulateTransactions`, or `starknet_estimateMessageFee` with `block_id = Tag(Pending)` during this window receives a `FeeEstimation` whose `l2_gas_price` field is `1` and whose `overall_fee` for V3 (STRK-denominated) transactions is computed against that corrupted price — off by a factor of ~10⁹ from the real value.

---

### Finding Description

**Step 1 — `read_pending_data` synthesizes a `DeprecatedPendingBlock` on hash mismatch** [1](#0-0) 

When `pending_data.block.parent_block_hash() != latest_header.block_hash`, the function constructs a `DeprecatedPendingBlock` using `..Default::default()`. It explicitly copies `eth_l1_gas_price`, `strk_l1_gas_price`, `timestamp`, `sequencer_address`, and `starknet_version` from the latest committed header — but there is no `l2_gas_price` field in `DeprecatedPendingBlock` to copy.

**Step 2 — `l2_gas_price()` on the `Deprecated` variant always returns zero** [2](#0-1) 

The comment "In older versions, L2 gas price was 0" explains the design intent for historical blocks, but this same code path is hit for the synthesized fallback block, which represents the *current* pending state.

**Step 3 — `client_pending_data_to_execution_pending_data` passes the zero price through** [3](#0-2) 

No clamping or substitution occurs here.

**Step 4 — `create_block_context` substitutes `NonzeroGasPrice::MIN` (= 1) for zero** [4](#0-3) 

Both `price_in_wei` and `price_in_fri` are zero, so both `eth_gas_prices.l2_gas_price` and `strk_gas_prices.l2_gas_price` become `NonzeroGasPrice::MIN` = `GasPrice(1)`. [5](#0-4) 

**Step 5 — `tx_execution_output_to_fee_estimation` reads the corrupted price into the response** [6](#0-5) 

The `l2_gas_price` field in the returned `FeeEstimation` is `1` (fri or wei). The `overall_fee` for V3 transactions is computed by blockifier using this same `BlockContext`, so it is also wrong.

**Step 6 — `estimate_fee` with `block_id=Pending` triggers this path** [7](#0-6) 

The same path is taken by `simulate_transactions` and `estimate_message_fee`. [8](#0-7) 

---

### Impact Explanation

- **`l2_gas_price` in the response** is `1` (fri) instead of the real value (~8×10⁹ fri on mainnet). This is a factor of ~8×10⁹ error.
- **`overall_fee`** for V3 (STRK-denominated) transactions is computed by blockifier against the corrupted `BlockContext`, so it is also massively underestimated.
- The response carries no error code or warning — it is indistinguishable from a correct estimate.
- Wallets and dApps that call `starknet_estimateFee` with `block_id=Pending` to set `max_fee` / resource bounds will set bounds far too low, causing transactions to fail on-chain with insufficient fee.
- The stale-pending window occurs on every block transition (every ~2–6 seconds on mainnet), making this a persistent, recurring condition rather than a rare edge case.

---

### Likelihood Explanation

The stale pending block condition is a normal operational state. The pending sync loop stops and restarts on every new block. Any `estimate_fee(block_id=Pending)` call that arrives during the gap between a new block being committed and the pending sync updating the shared `Arc<RwLock<PendingData>>` will hit this path. No attacker action is required; any unprivileged user calling the RPC during this window is affected.

---

### Recommendation

In `read_pending_data`, when synthesizing the fallback block, use a `PendingBlock` (the `Current` variant) instead of `DeprecatedPendingBlock`, and populate `l2_gas_price` from the latest committed block header's `l2_gas_price` field:

```rust
// Instead of DeprecatedPendingBlock { ..Default::default() }:
PendingBlockOrDeprecated::Current(PendingBlock {
    parent_block_hash: latest_header.block_hash,
    l1_gas_price: latest_header.block_header_without_hash.l1_gas_price,
    l1_data_gas_price: latest_header.block_header_without_hash.l1_data_gas_price,
    l2_gas_price: latest_header.block_header_without_hash.l2_gas_price,
    timestamp: latest_header.block_header_without_hash.timestamp,
    sequencer_address: latest_header.block_header_without_hash.sequencer,
    l1_da_mode: latest_header.block_header_without_hash.l1_da_mode,
    starknet_version: latest_header.block_header_without_hash.starknet_version.to_string(),
    ..Default::default()
})
```

This ensures the synthesized fallback block carries the real gas prices from the latest committed block rather than structural zeros.

---

### Proof of Concept

The existing test infrastructure already demonstrates the stale-pending path: [9](#0-8) 

A concrete regression test would:
1. Write a committed block with a real `l2_gas_price` (e.g., `8_000_000_000` fri).
2. Set `pending_data.block.parent_block_hash` to a random hash that does not match the committed block hash.
3. Call `starknet_estimateFee` with a V3 invoke transaction and `block_id = Tag(Pending)`.
4. Assert that `fee_estimation.l2_gas_price == 8_000_000_000` — this assertion will **fail** with the current code, returning `1` instead.

### Citations

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1009-1016)
```rust
        let maybe_pending_data = if let BlockId::Tag(Tag::Pending) = block_id {
            Some(client_pending_data_to_execution_pending_data(
                read_pending_data(&self.pending_data, &storage_txn).await?,
                self.pending_classes.read().await.clone(),
            ))
        } else {
            None
        };
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1079-1086)
```rust
        let maybe_pending_data = if let BlockId::Tag(Tag::Pending) = block_id {
            Some(client_pending_data_to_execution_pending_data(
                read_pending_data(&self.pending_data, &storage_txn).await?,
                self.pending_classes.read().await.clone(),
            ))
        } else {
            None
        };
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1570-1594)
```rust
    if pending_data.block.parent_block_hash() == latest_header.block_hash {
        Ok((*pending_data).clone())
    } else {
        Ok(PendingData {
            block: PendingBlockOrDeprecated::Deprecated(DeprecatedPendingBlock {
                parent_block_hash: latest_header.block_hash,
                eth_l1_gas_price: latest_header.block_header_without_hash.l1_gas_price.price_in_wei,
                strk_l1_gas_price: latest_header
                    .block_header_without_hash
                    .l1_gas_price
                    .price_in_fri,
                timestamp: latest_header.block_header_without_hash.timestamp,
                sequencer_address: latest_header.block_header_without_hash.sequencer,
                starknet_version: latest_header
                    .block_header_without_hash
                    .starknet_version
                    .to_string(),
                ..Default::default()
            }),
            state_update: ClientPendingStateUpdate {
                old_root: latest_header.block_header_without_hash.state_root,
                state_diff: Default::default(),
            },
        })
    }
```

**File:** crates/apollo_starknet_client/src/reader/objects/pending_data.rs (L162-168)
```rust
    pub fn l2_gas_price(&self) -> GasPricePerToken {
        match self {
            // In older versions, L2 gas price was 0.
            PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
            PendingBlockOrDeprecated::Current(block) => block.l2_gas_price,
        }
    }
```

**File:** crates/apollo_rpc/src/pending.rs (L20-20)
```rust
        l2_gas_price: client_pending_data.block.l2_gas_price(),
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L386-395)
```rust
                l2_gas_price: NonzeroGasPrice::new(l2_gas_price.price_in_wei)
                    .unwrap_or(NonzeroGasPrice::MIN),
            },
            strk_gas_prices: GasPriceVector {
                l1_gas_price: NonzeroGasPrice::new(l1_gas_price.price_in_fri)
                    .unwrap_or(NonzeroGasPrice::MIN),
                l1_data_gas_price: NonzeroGasPrice::new(l1_data_gas_price.price_in_fri)
                    .unwrap_or(NonzeroGasPrice::MIN),
                l2_gas_price: NonzeroGasPrice::new(l2_gas_price.price_in_fri)
                    .unwrap_or(NonzeroGasPrice::MIN),
```

**File:** crates/starknet_api/src/block.rs (L527-527)
```rust
    pub const MIN: Self = Self(GasPrice(1));
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L165-182)
```rust
    let gas_prices = &block_context.block_info().gas_prices;
    let (l1_gas_price, l1_data_gas_price, l2_gas_price) = (
        gas_prices.l1_gas_price(&tx_execution_output.price_unit.into()).get(),
        gas_prices.l1_data_gas_price(&tx_execution_output.price_unit.into()).get(),
        gas_prices.l2_gas_price(&tx_execution_output.price_unit.into()).get(),
    );

    let gas_vector = tx_execution_output.execution_info.receipt.gas;

    Ok(FeeEstimation {
        gas_consumed: gas_vector.l1_gas.0.into(),
        l1_gas_price,
        data_gas_consumed: gas_vector.l1_data_gas.0.into(),
        l1_data_gas_price,
        l2_gas_price,
        overall_fee: tx_execution_output.execution_info.receipt.fee,
        unit: tx_execution_output.price_unit,
    })
```

**File:** crates/apollo_rpc/src/v0_8/api/test.rs (L654-661)
```rust
    *pending_data.write().await.block.parent_block_hash_mutable() =
        BlockHash(random::<u64>().into());
    let res_block =
        module.call::<_, Block>(method_name, [BlockId::Tag(Tag::Pending)]).await.unwrap();
    let GeneralBlockHeader::PendingBlockHeader(pending_block_header) = res_block.header else {
        panic!("Unexpected block_header type. Expected PendingBlockHeader.")
    };
    assert_eq!(pending_block_header.parent_hash, block_hash);
```
