The code path is fully traceable. Let me confirm the exact `create_block_context` function signature and the `estimate_fee` call site.

The full chain is confirmed. Here is the complete analysis:

---

### Title
Stale Pending Block Synthesizes `DeprecatedPendingBlock` Without `l1_data_gas_price`, Causing `estimate_fee` with `block_id=Pending` to Return `l1_data_gas_price = 1` — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`)

### Summary

When the cached pending block is stale (its `parent_block_hash` does not match the latest committed block hash), `read_pending_data` synthesizes a fallback `DeprecatedPendingBlock`. This type has no `l1_data_gas_price` field; its `l1_data_gas_price()` method always returns `GasPricePerToken::default()` (zero). `create_block_context` then substitutes `NonzeroGasPrice::MIN` (= 1 wei) for the zero value. Any call to `estimate_fee` or `simulate_transactions` with `block_id=Pending` during this window returns a `FeeEstimation` with `l1_data_gas_price = 1` instead of the real network value, which on mainnet is typically in the giga-wei range.

### Finding Description

**Step 1 — `read_pending_data` synthesizes a `DeprecatedPendingBlock` on hash mismatch.**

When `pending_data.block.parent_block_hash() != latest_header.block_hash`, the function returns a synthesized block:

```rust
Ok(PendingData {
    block: PendingBlockOrDeprecated::Deprecated(DeprecatedPendingBlock {
        parent_block_hash: latest_header.block_hash,
        eth_l1_gas_price: latest_header.block_header_without_hash.l1_gas_price.price_in_wei,
        strk_l1_gas_price: latest_header.block_header_without_hash.l1_gas_price.price_in_fri,
        timestamp: ...,
        sequencer_address: ...,
        starknet_version: ...,
        ..Default::default()   // ← l1_data_gas_price is NOT copied from latest_header
    }),
    ...
})
``` [1](#0-0) 

The latest header's `l1_data_gas_price` field exists in `BlockHeaderWithoutHash` and is copied for `l1_gas_price`, but is **never copied** for `l1_data_gas_price`.

**Step 2 — `DeprecatedPendingBlock::l1_data_gas_price()` always returns zero.**

`DeprecatedPendingBlock` has no `l1_data_gas_price` field. The dispatch method hard-codes zero for the `Deprecated` variant:

```rust
pub fn l1_data_gas_price(&self) -> GasPricePerToken {
    match self {
        // In older versions, data gas price was 0.
        PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
        PendingBlockOrDeprecated::Current(block) => block.l1_data_gas_price,
    }
}
``` [2](#0-1) 

**Step 3 — `client_pending_data_to_execution_pending_data` passes the zero value through.** [3](#0-2) 

**Step 4 — `estimate_fee` with `block_id=Pending` uses this path.** [4](#0-3) 

**Step 5 — `create_block_context` substitutes `NonzeroGasPrice::MIN` (= 1) for the zero.**

```rust
l1_data_gas_price: NonzeroGasPrice::new(l1_data_gas_price.price_in_wei)
    .unwrap_or(NonzeroGasPrice::MIN),   // ← 0 → 1
``` [5](#0-4) 

`NonzeroGasPrice::MIN` is defined as `GasPrice(1)`: [6](#0-5) 

**Step 6 — `tx_execution_output_to_fee_estimation` reads `l1_data_gas_price` directly from the corrupted `BlockContext` and puts it in the RPC response.** [7](#0-6) 

### Impact Explanation

Any call to `starknet_estimateFee` or `starknet_simulateTransactions` with `block_id=Pending` during the stale-pending window returns a `FeeEstimation` where:

- `l1_data_gas_price` = 1 wei (instead of the real value, e.g., ~10^9 wei on mainnet)
- `overall_fee` is correspondingly underestimated for any transaction with nonzero `l1_data_gas` consumption (e.g., BLOB DA mode transactions, declare transactions)

This is an authoritative-looking wrong value returned by the RPC. Wallets and dApps that use `estimate_fee` to set `max_fee` or resource bounds will produce transactions that are under-resourced and will be rejected by the sequencer.

The same stale-path is also used by `simulate_transactions` and `estimate_message_fee` with `block_id=Pending`. [8](#0-7) [9](#0-8) 

### Likelihood Explanation

The stale-pending window is a **normal transient condition** that occurs on every block finalization: the committed block is written to storage before the pending data cache is refreshed. Any unprivileged user who calls `estimate_fee` with `block_id=Pending` during this window (which can last from milliseconds to seconds depending on sync latency) receives the corrupted value. No special privileges or adversarial setup are required.

### Recommendation

In the `else` branch of `read_pending_data`, use a `PendingBlock` (not `DeprecatedPendingBlock`) for the synthesized fallback, or explicitly copy `l1_data_gas_price` (and `l2_gas_price`, `l1_da_mode`) from `latest_header.block_header_without_hash`:

```rust
// In the mismatch branch, copy all gas prices from the latest committed header:
eth_l1_data_gas_price: latest_header.block_header_without_hash.l1_data_gas_price.price_in_wei,
strk_l1_data_gas_price: latest_header.block_header_without_hash.l1_data_gas_price.price_in_fri,
```

Alternatively, switch the synthesized fallback to `PendingBlockOrDeprecated::Current(PendingBlock { ... })` so that all gas price fields are explicitly populated from the latest header.

### Proof of Concept

```rust
// Pseudocode for a Rust integration test:
// 1. Write a committed block header with l1_data_gas_price = GasPricePerToken { price_in_wei: 1_000_000_000, price_in_fri: 2_000_000_000 }
// 2. Set pending_data.block.parent_block_hash to a random hash (mismatch)
// 3. Call estimate_fee with block_id=Tag(Pending) for a v3 invoke tx with nonzero L1_DATA_GAS resource bounds
// 4. Assert: fee_estimation.l1_data_gas_price == 1_000_000_000  // FAILS: actual is 1
```

The existing test at `crates/apollo_rpc/src/v0_8/api/test.rs` line 855–863 already exercises the stale-pending path for `get_block` but does **not** assert `l1_data_gas_price`, confirming the gap. [10](#0-9)

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

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1437-1444)
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

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1573-1594)
```rust
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

**File:** crates/apollo_starknet_client/src/reader/objects/pending_data.rs (L155-161)
```rust
    pub fn l1_data_gas_price(&self) -> GasPricePerToken {
        match self {
            // In older versions, data gas price was 0.
            PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
            PendingBlockOrDeprecated::Current(block) => block.l1_data_gas_price,
        }
    }
```

**File:** crates/apollo_rpc/src/pending.rs (L19-19)
```rust
        l1_data_gas_price: client_pending_data.block.l1_data_gas_price(),
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L384-385)
```rust
                l1_data_gas_price: NonzeroGasPrice::new(l1_data_gas_price.price_in_wei)
                    .unwrap_or(NonzeroGasPrice::MIN),
```

**File:** crates/starknet_api/src/block.rs (L527-527)
```rust
    pub const MIN: Self = Self(GasPrice(1));
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L166-178)
```rust
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
```

**File:** crates/apollo_rpc/src/v0_8/api/test.rs (L855-863)
```rust
    // Get pending block when it's not up to date.
    *pending_data.write().await.block.parent_block_hash_mutable() =
        BlockHash(random::<u64>().into());
    let res_block =
        module.call::<_, Block>(method_name, [BlockId::Tag(Tag::Pending)]).await.unwrap();
    let GeneralBlockHeader::PendingBlockHeader(pending_block_header) = res_block.header else {
        panic!("Unexpected block_header type. Expected PendingBlockHeader.")
    };
    assert_eq!(pending_block_header.parent_hash, block_hash);
```
