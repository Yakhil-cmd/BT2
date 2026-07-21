The full code path is confirmed. Here is the analysis:

---

### Title
Stale Pending Block Fallback Silently Clamps `l1_data_gas_price` and `l2_gas_price` to `NonzeroGasPrice::MIN` in `estimateFee` — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`, `crates/apollo_rpc_execution/src/lib.rs`)

### Summary

When the node's cached pending data is stale (its `parent_block_hash` does not match the latest committed block hash), `read_pending_data` constructs a `DeprecatedPendingBlock` fallback. This fallback type has no `l1_data_gas_price` or `l2_gas_price` fields, so both accessors return `GasPricePerToken::default()` = `(0, 0)`. These zeros propagate through `client_pending_data_to_execution_pending_data` into `ExecutionPendingData`, and `create_block_context` silently clamps them to `NonzeroGasPrice::MIN` (= 1). Any call to `starknet_estimateFee` or `starknet_simulateTransactions` with `block_id = Pending` during this stale window returns fee estimates computed against a data-gas price of 1 instead of the real committed value.

### Finding Description

**Step 1 — Stale fallback construction.**

`read_pending_data` compares `pending_data.block.parent_block_hash()` to `latest_header.block_hash`. When they differ it builds:

```rust
PendingBlockOrDeprecated::Deprecated(DeprecatedPendingBlock {
    parent_block_hash: latest_header.block_hash,
    eth_l1_gas_price: latest_header…l1_gas_price.price_in_wei,
    strk_l1_gas_price: latest_header…l1_gas_price.price_in_fri,
    timestamp: …,
    sequencer_address: …,
    starknet_version: …,
    ..Default::default()   // ← no l1_data_gas_price, no l2_gas_price
})
``` [1](#0-0) 

**Step 2 — Accessors return zero.**

`DeprecatedPendingBlock` has no `l1_data_gas_price` or `l2_gas_price` fields. Both accessors on the `Deprecated` variant explicitly return `GasPricePerToken::default()` = `(0, 0)`:

```rust
pub fn l1_data_gas_price(&self) -> GasPricePerToken {
    match self {
        PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
        …
    }
}
pub fn l2_gas_price(&self) -> GasPricePerToken {
    match self {
        PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
        …
    }
}
``` [2](#0-1) 

**Step 3 — Zeros propagate into `ExecutionPendingData`.**

`client_pending_data_to_execution_pending_data` directly assigns the accessor results:

```rust
l1_data_gas_price: client_pending_data.block.l1_data_gas_price(),
l2_gas_price:      client_pending_data.block.l2_gas_price(),
``` [3](#0-2) 

**Step 4 — `create_block_context` silently clamps zeros to `NonzeroGasPrice::MIN`.**

```rust
l1_data_gas_price: NonzeroGasPrice::new(l1_data_gas_price.price_in_wei)
    .unwrap_or(NonzeroGasPrice::MIN),   // 0 → 1
l2_gas_price: NonzeroGasPrice::new(l2_gas_price.price_in_wei)
    .unwrap_or(NonzeroGasPrice::MIN),   // 0 → 1
```

The adjacent TODO comment confirms the team is aware this path exists: `// TODO(yair): What to do about blocks pre 0.13.1 where the data gas price were 0?` [4](#0-3) 

**Step 5 — `estimate_fee` and `simulate_transactions` both hit this path.**

Both RPC handlers call `read_pending_data` → `client_pending_data_to_execution_pending_data` → `exec_estimate_fee` / `exec_simulate_transactions` with the corrupted `maybe_pending_data`. [5](#0-4) [6](#0-5) 

**Contrast with the non-stale path.** When `parent_block_hash` matches, the real `PendingBlock` (variant `Current`) is returned, and its `l1_data_gas_price` and `l2_gas_price` fields carry the actual values. The fallback intentionally uses `DeprecatedPendingBlock` — a type designed for pre-0.13.1 blocks where those prices were legitimately zero — but applies it to modern blocks where they are not. [7](#0-6) 

### Impact Explanation

During the stale window (which occurs naturally at every block boundary while the pending-sync loop fetches fresh data), any caller of `starknet_estimateFee` or `starknet_simulateTransactions` with `block_id = Pending` receives:

- `l1_data_gas_price` = 1 (instead of the real committed value, which on mainnet is on the order of billions of wei/fri)
- `l2_gas_price` = 1 (same)
- `overall_fee` computed against these wrong prices — potentially orders of magnitude too low

The response is structurally valid and indistinguishable from a correct estimate. A wallet or dApp that trusts the returned `overall_fee` to set `max_fee` or resource bounds will produce transactions that are under-priced relative to the actual pending block context, leading to rejection or unexpected revert at the gateway/mempool.

This matches the allowed impact: **High — RPC fee estimation returns an authoritative-looking wrong value.**

### Likelihood Explanation

The stale window is not user-forced but is a normal operational condition. It occurs at every block transition (roughly every few seconds on Starknet mainnet) for the duration between the storage writer committing a new block and the pending-sync loop writing fresh pending data. Any client polling `estimateFee` at `Pending` during this window is affected. The window length depends on network latency to the feeder gateway, but is reliably non-zero.

### Recommendation

In the stale-fallback branch of `read_pending_data`, copy `l1_data_gas_price` and `l2_gas_price` from the latest committed header, exactly as is already done for `l1_gas_price`. Since `DeprecatedPendingBlock` has no fields for these, either:

1. Switch the fallback to construct a `PendingBlock` (variant `Current`) populated from the latest header, or
2. Store the data-gas and L2-gas prices separately and return them from a new fallback struct that carries all six price fields.

Additionally, remove the silent `.unwrap_or(NonzeroGasPrice::MIN)` clamping in `create_block_context` for the pending path, or at minimum emit a warning/error so the condition is observable.

### Proof of Concept

```rust
// Pseudocode for a Rust integration test
// 1. Write one committed block with non-zero l1_data_gas_price and l2_gas_price.
let l1_data_gas_price = GasPricePerToken { price_in_wei: 1_000_000_000u128.into(), price_in_fri: 2_000_000_000u128.into() };
let l2_gas_price      = GasPricePerToken { price_in_wei: 3_000_000_000u128.into(), price_in_fri: 4_000_000_000u128.into() };
write_block_with_prices(&storage_writer, l1_data_gas_price, l2_gas_price);

// 2. Set pending_data.block.parent_block_hash to a random hash (stale).
*pending_data.write().await.block.parent_block_hash_mutable() = BlockHash(Felt::from(0xdeadbeef_u64));

// 3. Call estimateFee with block_id = Pending.
let fees = module.call::<_, Vec<FeeEstimation>>(
    "starknet_V0_8_estimateFee",
    (vec![some_invoke_tx], vec![], BlockId::Tag(Tag::Pending)),
).await.unwrap();

// 4. Assert that the returned prices equal NonzeroGasPrice::MIN (= 1), not the committed values.
assert_eq!(fees[0].l1_data_gas_price, GasPrice(1));  // corrupted
assert_ne!(fees[0].l1_data_gas_price, l1_data_gas_price.price_in_wei); // should have been real price
```

The test would pass against the current code, confirming the corruption.

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

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1573-1593)
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
```

**File:** crates/apollo_starknet_client/src/reader/objects/pending_data.rs (L155-168)
```rust
    pub fn l1_data_gas_price(&self) -> GasPricePerToken {
        match self {
            // In older versions, data gas price was 0.
            PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
            PendingBlockOrDeprecated::Current(block) => block.l1_data_gas_price,
        }
    }
    pub fn l2_gas_price(&self) -> GasPricePerToken {
        match self {
            // In older versions, L2 gas price was 0.
            PendingBlockOrDeprecated::Deprecated(_) => GasPricePerToken::default(),
            PendingBlockOrDeprecated::Current(block) => block.l2_gas_price,
        }
    }
```

**File:** crates/apollo_starknet_client/src/reader/objects/pending_data.rs (L197-228)
```rust
#[derive(Debug, Default, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PendingBlock {
    #[serde(flatten)]
    pub accepted_on_l2_extra_data: Option<AcceptedOnL2ExtraData>,
    pub parent_block_hash: BlockHash,
    pub status: BlockStatus,
    pub l1_gas_price: GasPricePerToken,
    pub l1_data_gas_price: GasPricePerToken,
    #[serde(default)]
    pub l2_gas_price: GasPricePerToken,
    pub transactions: Vec<Transaction>,
    pub timestamp: BlockTimestamp,
    pub sequencer_address: SequencerContractAddress,
    pub transaction_receipts: Vec<TransactionReceipt>,
    pub starknet_version: String,
    pub l1_da_mode: L1DataAvailabilityMode,
    // TODO(shahak): Consider adding fee market info fields by adding withFeeMarketInfo=true to the
    // feeder request.

    // We do not care about commitments in pending blocks.
    #[serde(default)]
    pub transaction_commitment: Option<TransactionCommitment>,
    #[serde(default)]
    pub event_commitment: Option<EventCommitment>,
    #[serde(default)]
    pub receipt_commitment: Option<ReceiptCommitment>,
    #[serde(default)]
    pub state_diff_commitment: Option<StateDiffCommitment>,
    #[serde(default)]
    pub state_diff_length: Option<usize>,
}
```

**File:** crates/apollo_rpc/src/pending.rs (L19-20)
```rust
        l1_data_gas_price: client_pending_data.block.l1_data_gas_price(),
        l2_gas_price: client_pending_data.block.l2_gas_price(),
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L379-396)
```rust
        // TODO(yair): What to do about blocks pre 0.13.1 where the data gas price were 0?
        gas_prices: GasPrices {
            eth_gas_prices: GasPriceVector {
                l1_gas_price: NonzeroGasPrice::new(l1_gas_price.price_in_wei)
                    .unwrap_or(NonzeroGasPrice::MIN),
                l1_data_gas_price: NonzeroGasPrice::new(l1_data_gas_price.price_in_wei)
                    .unwrap_or(NonzeroGasPrice::MIN),
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
            },
```
