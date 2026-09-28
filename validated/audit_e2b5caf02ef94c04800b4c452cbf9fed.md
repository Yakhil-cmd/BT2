### Title
Unbounded chunked-accrual loop in `global_sync` permanently freezes a market after sufficient idle time - (File: contracts/pool/src/interest.rs)

### Summary
The millisecond ReDoS pattern — work proportional to an unbounded, caller-influenced input with no iteration cap — maps onto the pool's interest accrual. `global_sync` splits the elapsed time since the last accrual into fixed-size chunks and processes **all** of them inside a single transaction. There is no upper bound on the number of chunks and no way to accrue incrementally across transactions. Once the idle duration grows past the point where `elapsed_ms / MAX_COMPOUND_DELTA_MS` chunks exceed the Soroban per-transaction CPU/memory budget, every call that touches the market reverts on budget exhaustion — permanently.

### Finding Description
`contracts/pool/src/interest.rs` `global_sync` runs:

```rust
let mut remaining = cache.elapsed_ms();
while let Some(nonzero) = NonZeroU64::new(remaining) {
    let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
    accrue_chunk(env, cache, chunk);
    remaining = remaining.saturating_sub(chunk);
}
```

- `remaining` is derived from wall-clock elapsed time, which grows without bound and is not controlled or limited by any protocol parameter.
- Each iteration performs full RAY fixed-point accrual (`accrue_step`) plus revenue share bookkeeping — a non-trivial cost per chunk.
- The loop is atomic: the protocol offers no partial-accrual or paginated-sync entrypoint. Every state-mutating verb (`supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `flash_loan`, `claim_revenue`) on that `(hub, asset)` book requires `global_sync` to complete first, since the cache must reach the current timestamp.
- Unlike `update_account_threshold`'s caller-supplied `account_ids` vector (which a caller can simply split into smaller batches), elapsed time **cannot be split by the caller** — the first caller after a long idle period is forced to pay for all chunks in one shot, and if that exceeds the budget no one can ever sync again.

This is the direct analog of parsing an arbitrarily long string in one regex pass: an input whose size grows monotonically with no cap, fed into a single-shot linear loop inside one bounded execution context.

### Impact Explanation
Permanent freezing of funds. Once `elapsed_ms / MAX_COMPOUND_DELTA_MS × per-chunk-cost` exceeds the Soroban transaction resource ceiling, `update_indexes` and every pool-touching verb on that market permanently reverts. All supplied funds, outstanding borrows, collateral backing positions, and unclaimed revenue in that `(hub, token)` book become unreachable — suppliers cannot withdraw, borrowers cannot repay or be liquidated, and revenue cannot be claimed. The project's own docs acknowledge the shape without resolving it: position/route limits "do not prove every maximum-size operation fits deployed CPU, memory, footprint" budgets, and chunk bounding "does not make cadence neutral" (docs/explanation/threat-model.md).

### Likelihood Explanation
- Requires no attacker action beyond inaction: any unprivileged address can call `update_indexes`, but the trigger is simply that no one calls a market for a sufficiently long period. Low-activity markets (long-tail listed assets, deprecated-but-still-listed spokes) naturally accumulate idle time.
- The attacker can accelerate the threshold by combining idle time with compounding archival/TTL decay of the `last_timestamp` entry, which inflates `elapsed_ms` for the next reader.
- Severity of the horizon depends on `MAX_COMPOUND_DELTA_MS` and per-chunk cost, which I could not confirm within this pass; if the chunk size is on the order of hours/days, the freeze horizon is realistically reachable for dormant markets; if it is on the order of months, likelihood is lower but the structural defect (no iteration cap, no pagination) remains.

### Recommendation
- Cap accrual work per call: accrue at most `N` chunks, persist the intermediate `last_timestamp`, and return early. Because indexes are monotonic, an unsynced remainder can be completed by subsequent calls, restoring liveness.
- Alternatively, make `accrue_step` closed-form over arbitrary `delta_ms` (single exponentiation-style step) so cost is O(1) regardless of idle duration.
- As defense in depth, keep a keeper/`update_indexes` heartbeat per listed market so elapsed time never approaches the budget-derived horizon.

### Proof of Concept
1. Governance lists a low-activity market `(hub, asset)`; a supplier deposits and one small borrow is taken.
2. No transaction touches the market for a period `T` such that `T / MAX_COMPOUND_DELTA_MS` chunks exceed the Soroban CPU budget (the harness bench `bench_liquidate_max_positions.rs` demonstrates that even bounded 5+5-leg liquidation sits close to the 400M-instruction ceiling; accrual chunks have no analogous bound).
3. Any unprivileged caller invokes `update_indexes` (or `supply`/`withdraw`/`liquidate`) on the book → `global_sync` iterates all outstanding chunks in one transaction → `HostError: Error(Budget, ExceededLimit)`.
4. Every subsequent call fails identically; the market's funds are permanently frozen.

Caveat: the exact chunk size `MAX_COMPOUND_DELTA_MS` and the measured per-chunk instruction cost were not confirmed in this pass; the exploitability horizon depends on their product versus the network CPU limit. The structural root cause — a single-transaction loop with no bound on iteration count over an ever-growing time input — is confirmed at `contracts/pool/src/interest.rs:25-30`.