The code evidence is clear. Let me trace the full path.

## Code Trace

**Step 1 — Stale pending fallback in `read_pending_data`**

When `pending_data.block.parent_block_hash() != latest_header.block_hash`, the fallback is: [1](#0-0) 

The fallback constructs a `DeprecatedPendingBlock` and copies only `eth_l1_gas_price` (← `l1_gas_price.price_in_wei`) and `strk_l1_gas_price` (← `l1_gas_price.price_in_fri`) from the latest header. The latest header's `l1_data_gas_price` and `l2_gas_price` fields are **not copied**. The rest is `..Default::default()`.

**Step 2 — `DeprecatedPendingBlock` structurally cannot carry those fields** [2](#0-1) 

`DeprecatedPendingBlock` has no `l1_data_gas_price` or `l2_gas_price` fields at all. Only `PendingBlock` (the `Current` variant) carries them.

**Step 3 — Accessor methods return zero for `Deprecated`** [3](#0-2) 

Both `l1_data_gas_price()` and `l2_gas_price()` explicitly return `GasPricePerToken::default()` (all-zero) for the `Deprecated` variant, with comments acknowledging this is intentional for old blocks.

**Step 4 — Zero prices flow into execution** [4](#0-3) 

`client_pending_data_to_execution_pending_data` calls `.l1_data_gas_price()` and `.l2_gas_price()` directly on the block, so zero propagates into `ExecutionPendingData`.

---

## Verdict

### Title
Stale Pending Fallback Zeroes `l1_data_gas_price` and `l2_gas_price`, Corrupting `estimateFee` for V3 Transactions — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`)

### Summary
When the cached pending block is stale (its `parent_block_hash` does not match the latest committed block hash), `read_pending_data` constructs a `DeprecatedPendingBlock` fallback that structurally cannot carry `l1_data_gas_price` or `l2_gas_price`. Both accessors return zero. These zero prices flow through `client_pending_data_to_execution_pending_data` into `create_block_context`, causing `estimateFee` with `block_id=Pending` to compute a zero (or `NonzeroGasPrice::MIN`-clamped) data-gas and L2-gas fee component for V3 transactions.

### Finding Description
`read_pending_data` has two branches:
- **Fresh path** (line 1570–1571): returns the cached `PendingData` as-is, which is a `PendingBlockOrDeprecated::Current` carrying all three price fields.
- **Stale path** (lines 1573–1594): constructs a `DeprecatedPendingBlock` with only `eth_l1_gas_price` and `strk_l1_gas_price` populated from the latest header. `l1_data_gas_price` and `l2_gas_price` are absent from the struct entirely.

The `l1_data_gas_price()` and `l2_gas_price()` methods on `PendingBlockOrDeprecated` return `GasPricePerToken::default()` (zero) for any `Deprecated` variant. This is correct for genuinely old blocks that predate those fields, but incorrect here — the latest committed header does carry non-zero values for both fields, and the fallback simply fails to copy them.

The stale condition is a normal operational state: it occurs whenever a new block is committed but the pending-block cache has not yet been refreshed. Any unprivileged user can trigger this path by calling `estimateFee` with `block_id=Pending` during that window.

### Impact Explanation
For a V3 transaction that consumes data gas or L2 gas, the `overall_fee` returned by `estimateFee` will be computed with zero (or MIN-clamped) prices for those components. The returned estimate is lower than the fee that will actually be charged at sequencing time. A client that uses the estimate to set `resource_bounds` may submit a transaction that is rejected or reverted due to insufficient fee bounds. This matches the allowed scope: **"RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."**

### Likelihood Explanation
The stale window exists on every block transition. On a chain producing blocks every few seconds, the window is short but continuous and requires no special timing or privileges to hit — any `estimateFee` call during the window is affected.

### Recommendation
Replace the `DeprecatedPendingBlock` fallback with a `PendingBlockOrDeprecated::Current(PendingBlock { ... })` that copies all price fields from the latest header, including `l1_data_gas_price` and `l2_gas_price`. The latest `BlockHeaderWithoutHash` already carries these fields; they just need to be forwarded.

### Proof of Concept
1. Commit a block with `l1_data_gas_price.price_in_wei = 1000`, `l2_gas_price.price_in_wei = 500`.
2. Ensure the RPC node's pending-block cache still points to the previous block (stale condition).
3. Call `estimateFee` with `block_id = Pending` and a V3 transaction that consumes data gas.
4. Observe that the `l1_data_gas_price` in the returned `FeeEstimation` is `0` or `NonzeroGasPrice::MIN` rather than `1000`, and `overall_fee` is correspondingly underestimated.

### Citations

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

**File:** crates/apollo_starknet_client/src/reader/objects/pending_data.rs (L178-195)
```rust
#[derive(Debug, Default, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeprecatedPendingBlock {
    #[serde(flatten)]
    pub accepted_on_l2_extra_data: Option<AcceptedOnL2ExtraData>,
    pub parent_block_hash: BlockHash,
    pub status: BlockStatus,
    // In older versions, eth_l1_gas_price was named gas_price and there was no strk_l1_gas_price.
    #[serde(alias = "gas_price")]
    pub eth_l1_gas_price: GasPrice,
    #[serde(default)]
    pub strk_l1_gas_price: GasPrice,
    pub transactions: Vec<Transaction>,
    pub timestamp: BlockTimestamp,
    pub sequencer_address: SequencerContractAddress,
    pub transaction_receipts: Vec<TransactionReceipt>,
    pub starknet_version: String,
}
```

**File:** crates/apollo_rpc/src/pending.rs (L18-21)
```rust
        l1_gas_price: client_pending_data.block.l1_gas_price(),
        l1_data_gas_price: client_pending_data.block.l1_data_gas_price(),
        l2_gas_price: client_pending_data.block.l2_gas_price(),
        l1_da_mode: client_pending_data.block.l1_da_mode(),
```
