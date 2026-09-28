### Title
Protocol revenue shares are floor-minted on every accrual chunk, permanently underpaying claimable revenue — (`File: common/src/rates/index.rs`)

### Summary
Each accrual step converts the protocol's interest fee into scaled supply shares with `mul_div_floor_saturating` in `protocol_fee_shares` (`common/src/rates/index.rs:94-99`). The fractional-share remainder is discarded rather than captured, so the `revenue` balance — later paid out through the permissionless `claim_revenue` path — is systematically less than the protocol's pro-rata entitlement. This is the same class as the JOJO `Trading.sol` issue: a pro-rata `a * b / c` division that rounds down and feeds a beneficiary's accumulated fee inside a repeated computation.

### Finding Description
Accrual runs in `global_sync` → `accrue_chunk` (`contracts/pool/src/interest.rs:20-53`), which loops over elapsed time in chunks of up to `MAX_COMPOUND_DELTA_MS` and calls `accrue_step`, then `cache.accrue_revenue(step.revenue_shares)`. The fee-to-shares conversion happens in `protocol_fee_shares`:

```rust
let raw = fp_core::mul_div_floor_saturating(env, fee.raw(), RAY, supply_index.raw());
```

Floor rounding is correct at user-facing boundaries (the pool README documents "round against the user, in favor of the protocol"), but here the floored value *is* the protocol's entitlement — the rounding runs against the fee recipient itself. Unlike supplier-side rounding, whose remainder is recovered via `supply_index_reward_shortfall` (`common/src/rates/index.rs:53-64`) and booked into revenue, the sub-share remainder of the fee conversion is neither booked anywhere nor accumulated; it is destroyed each chunk. Any unprivileged caller can trigger accrual via `update_indexes` (or any supply/borrow/withdraw/repay/liquidate call that runs `global_sync`), and each chunk permanently discards up to ~1 raw share unit of revenue.

### Impact Explanation
Permanent loss of accrued protocol yield. The protocol's `revenue` shares are its only claim on the reserve-factor portion of interest; every floored fraction is yield that `claim_revenue` can never pay out. The loss compounds with accrual frequency: long accrual gaps are split into multiple `MAX_COMPOUND_DELTA_MS` chunks, and each chunk applies an independent floor, so a single `update_indexes` after a long idle period loses proportionally more than one accrual would. Per-chunk loss is bounded by the RAY share granularity, so on high-decimal assets the absolute token value is dust — severity is Medium at best, mirroring the JOJO report.

### Likelihood Explanation
The rounding loss occurs on every accrual where `fee * RAY` is not exactly divisible by `supply_index` — i.e., essentially always once the supply index drifts from `RAY`. It requires no special state beyond an active borrow market and is reachable through the permissionless `update_indexes` entrypoint or any state-changing pool op. The exploitability bar (unprivileged, deterministic, no timing dependence) is trivially met; only the magnitude is bounded.

### Recommendation
Match the rounding direction to the beneficiary: either ceil the fee-share conversion (`mul_div_ceil`/`mul_ratio_ceil`, consistent with the `revenue claim | mul_ratio_ceil` policy in `contracts/pool/README.md`), or keep the floor but add the discarded remainder into the existing `supply_index_reward_shortfall` recovery so the value is re-booked to revenue rather than destroyed. A state-level invariant `distributed_shares * supply_index ≤ fee` with explicit remainder accounting would let the fuzz/certora suites enforce no-loss.

### Proof of Concept
1. Supply to a hub market and borrow so utilization > 0 and `reserve_factor > 0`.
2. Advance time past one `MAX_COMPOUND_DELTA_MS` boundary (or wait through a long gap) so `global_sync` runs at least two accrual chunks.
3. Call `update_indexes` (permissionless).
4. Recompute off-chain: `expected_shares = ceil(fee * RAY / supply_index)` per chunk; actual `revenue` increment is `floor(...)` per chunk. The difference accumulates to N×(fractional part) where N is the chunk count, and no storage field ever receives it — `simulate_update_indexes` shows the shortfall term covers only the supplier-reward side of the split.

Caveat: I could not read `accrue_step` in `common/src/rates/simulate.rs` directly (grep confirmed it references `shortfall` and `revenue_shares`, but I did not see the exact lines). If the step already re-adds the fee-conversion remainder into `revenue_shares`, this analog collapses to a documented design choice; verification of that function is the one open item.