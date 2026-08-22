### Title
Hint-scan height iteration in `resolve_receipt_via_hint` is unmetered by the shared outcome budget, allowing per-hop `Ancestor` scans to add O(depth × max_hop_distance) unbudgeted DB lookups - (File: chain/chain/src/receipt_to_tx.rs)

### Summary
`resolve_receipt_via_hint` charges `remaining_budget` only when an outcome is inspected, not when a height is visited, so heights with zero (or GC'd) outcomes for the target shard cost two DB reads (`get_block_hash_by_height` + `get_outcomes_by_block_hash_and_shard_id`) each without decrementing the shared budget. Because every hop after the first scan-resolved hop runs in `Scan::Ancestor { max_distance: max_hop_distance }` regardless of the caller-supplied `window`, a long `FromReceipt` chain with `save_receipt_to_tx=false` can force up to `depth` hops, each re-walking up to `max_hop_distance` heights, turning the intended single-`width`-bounded cost into a `depth × max_hop_distance` cost that the outcome budget does not see.

### Finding Description
`resolve_receipt_via_hint` iterates candidate heights and only performs budget accounting inside the inner per-outcome loop: [1](#0-0) 

The outer `for height in heights` loop unconditionally calls `chain_store.get_block_hash_by_height(height)` and, on success, `chain_store.get_outcomes_by_block_hash_and_shard_id(...)` before any budget check occurs; `remaining_budget` is only tested/decremented once an `outcome_id` exists to inspect. If a height has no outcomes on the target shard (common for a shard with light traffic, or heights that were pruned/never populated on that shard), the height is "free" from the budget's perspective yet still costs the two DB reads plus the `heights_scanned` increment.

The scan mode escalates and stays escalated: once any hop in the walk is resolved via scan (rather than via the `ReceiptToTx` column), all subsequent hops use `Scan::Ancestor { max_distance: max_hop_distance }`, independent of whatever `window` the caller originally supplied: [2](#0-1) [3](#0-2) 

This is documented as intentional monotonic behavior ("once the walker resolves a hop via scan it stays in `Ancestor` for the rest of the walk"). The code comment on the budget itself confirms it is a single pool shared across the whole multi-hop walk, gating only *outcome* inspection, not height iteration: "`remaining_budget` decrements per outcome inspected — one budget shared across all shards + hops." [4](#0-3) 

The RPC-facing error surface confirms a `WindowTooLarge` cap exists on the caller-supplied `window` and a separate `DepthExceeded` cap exists on hop count, and a `BudgetExceeded` error surfaces when the shared outcome budget is exhausted: [5](#0-4) 

Because `DepthExceeded`/`WindowTooLarge`/`BudgetExceeded` exist as distinct, independently-configured limits, and only the outcome-inspection cost is metered against `BudgetExceeded`, an attacker can pick `window` just under the max allowed and construct (or locate) a `FromReceipt` chain of near-maximum depth on a shard where most candidate heights have no outcomes for that shard. Each hop then performs up to `max_hop_distance` "free" height-level DB lookups that never trip `remaining_budget`, so the total unbudgeted height-lookup work scales as `depth × max_hop_distance` rather than being bounded once by a single width parameter as the budget design intends.

Note: I was not able to fully read the depth-driving loop and its exact numeric limits in `chain/client/src/view_client_actor.rs` (ran out of tool iterations after confirming the relevant symbols exist there: `max_hop_distance`, `remaining_budget`, `DepthExceeded`, `BudgetExceeded`, `depth`). The finding above is fully supported by `chain/chain/src/receipt_to_tx.rs`, which is the function named in the question's scope; the exact configured values of `max_hop_distance`, `receipt_to_tx_max_hint_window`, and the depth cap in `view_client_actor.rs`/`client_config.rs` were not independently confirmed in this pass.

### Impact Explanation
This is a view-client/RPC resource-consumption issue, not a consensus, balance, or authorization bypass. Impact class: unbounded/disproportionate resource use on a public read-only RPC endpoint (`receipt_to_tx`), callable by any unprivileged caller, causing the node to perform substantially more DB point-lookups than the budget parameter is designed to allow per call. Severity is bounded by the configured `max_hop_distance` and depth-limit constants (finite, not literally infinite), so this is a metering-gap / amplification issue rather than a full denial-of-service primitive, unless those constants are configured large.

### Likelihood Explanation
Requires: (1) `save_receipt_to_tx=false` or equivalent condition forcing the hint-scan fallback rather than the indexed `ReceiptToTx` column path, (2) a real or attacker-constructed chain of `FromReceipt` hops of near-maximum depth, (3) heights along the ancestor walk on the relevant shard that mostly lack outcomes (plausible on low-traffic shards), and (4) a caller-supplied `window` near `receipt_to_tx_max_hint_window` to also maximize the first-hop cost. These preconditions are all achievable by an ordinary RPC caller without any privileged access, but constructing a shard/height layout that maximizes "empty" ancestor heights across `depth` hops is non-trivial and depends on chain history rather than being purely attacker-controlled input.

### Recommendation
Charge `remaining_budget` per height visited in the outer loop of `resolve_receipt_via_hint` (not only per outcome inspected), or apply a separate, explicit total-heights-scanned cap shared across the whole multi-hop walk (mirroring the existing shared outcome budget). This restores the invariant that total node work per RPC call is bounded by a single width-like parameter rather than `width × depth`.

### Proof of Concept
Integration test (extending `test-loop-tests/src/tests/receipt_to_tx/budget.rs` and `hint.rs` patterns):
1. Build a chain of ~999 `FromReceipt` hops on a shard, with most ancestor heights along each hop's `[h-max_hop_distance, h]` window free of outcomes for that shard.
2. Call `receipt_to_tx` with `window` set to just under `receipt_to_tx_max_hint_window`, `save_receipt_to_tx=false`.
3. Instrument `HintScanStats::heights_scanned` accumulated across the whole call.
4. Assert `heights_scanned > receipt_to_tx_max_hint_window + max_hop_distance` (i.e., grows with hop count) while `outcomes_scanned` (and thus the budget consumed) stays near zero, demonstrating that height-level work is not gated by `remaining_budget`/`BudgetExceeded`, contrary to the intended single-width metering invariant.

### Citations

**File:** chain/chain/src/receipt_to_tx.rs (L16-31)
```rust
/// Default `Scan::CenterOut` window (blocks) when caller omits `window`.
/// Scan inspects `[h-window, h+window]`. `Scan::Ancestor` uses
/// `receipt_to_tx_max_hop_distance` instead.
pub const DEFAULT_HINT_WINDOW: BlockHeightDelta = 5;

/// Hint scan mode + width. Monotonic: once the walker resolves a hop via
/// scan it stays in `Ancestor` for the rest of the walk; column hits do
/// not flip it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// `±window` around the caller's literal hint. Used pre-first-scan.
    CenterOut { window: BlockHeightDelta },
    /// Anchor-inclusive backward scan `h, h-1, ..., h-max_distance`.
    /// Used after any prior hop in the walk was scan-resolved.
    Ancestor { max_distance: BlockHeightDelta },
}
```

**File:** chain/chain/src/receipt_to_tx.rs (L67-77)
```rust
/// Iterate heights backward `h, h-1, ..., h-max_distance`, saturating at 0.
/// Anchor included so scan finds same-shard local receipts (execute in
/// same block as producing outcome). No forward heights — receipts emit
/// before execute.
fn ancestor_heights(
    block_height: BlockHeight,
    max_distance: BlockHeightDelta,
) -> impl Iterator<Item = BlockHeight> {
    let (lo, hi) = (Scan::Ancestor { max_distance }).height_bounds(block_height);
    (lo..=hi).rev()
}
```

**File:** chain/chain/src/receipt_to_tx.rs (L115-119)
```rust
/// `stats` accumulates in-place (callers emit metrics on hit/miss/error).
/// Missing data (no block at height, GC'd outcome, deleted receipt) is
/// skip-and-continue. `remaining_budget` decrements per outcome inspected
/// — one budget shared across all shards + hops.
pub fn resolve_receipt_via_hint(
```

**File:** chain/chain/src/receipt_to_tx.rs (L134-149)
```rust
    for height in heights {
        stats.heights_scanned += 1;
        let block_hash = match chain_store.get_block_hash_by_height(height) {
            Ok(h) => h,
            Err(Error::DBNotFoundErr(_)) => continue,
            Err(e) => return Err(e.into()),
        };

        let outcome_ids =
            chain_store.get_outcomes_by_block_hash_and_shard_id(&block_hash, shard_id);
        for outcome_id in outcome_ids {
            if *remaining_budget == 0 {
                return Err(ResolveHintError::BudgetExceeded);
            }
            *remaining_budget -= 1;
            stats.outcomes_scanned += 1;
```

**File:** chain/jsonrpc/src/api/receipts.rs (L62-76)
```rust
            GetReceiptToTxError::UnknownReceipt(receipt_id) => Self::UnknownReceipt { receipt_id },
            GetReceiptToTxError::DepthExceeded { receipt_id, limit } => {
                Self::DepthExceeded { receipt_id, limit }
            }
            GetReceiptToTxError::Unsupported(error_message) => Self::Unsupported { error_message },
            GetReceiptToTxError::OutcomesNotStored => Self::OutcomesNotStored,
            GetReceiptToTxError::WindowTooLarge { requested, maximum } => {
                Self::WindowTooLarge { requested, maximum }
            }
            GetReceiptToTxError::MalformedHint(error_message) => {
                Self::MalformedHint { error_message }
            }
            GetReceiptToTxError::BudgetExceeded { scanned, limit } => {
                Self::BudgetExceeded { scanned, limit }
            }
```
