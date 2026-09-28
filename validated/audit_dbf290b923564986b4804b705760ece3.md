### Title
Revenue claims permanently revert when debt exceeds `max_utilization` of non-revenue supply — (File: contracts/pool/src/ops/revenue.rs)

### Summary
`pool::ops::revenue::accounting` burns claimable revenue shares and *then* runs `guards::require_utilization_below_max` on the post-burn cache. Because revenue shares are a subset of `supplied` (`accrue_revenue`/`burn_claimable_revenue` move both in lockstep), every burn lowers the utilization denominator. Whenever outstanding debt exceeds `max_utilization` times the value of *user* supply alone, the full-treasury burn pushes computed utilization above `max_utilization` and the transaction always reverts. A single unprivileged borrower who keeps debt outstanding at that level makes `claim_revenue` unreachable — the analog of the Trident `claimReward` that always reverts, here caused by a guard applied *after* the mutation that determines whether the check passes.

### Finding Description
`contracts/pool/src/ops/revenue.rs:39-48` executes, in order:

```rust
let net_transfer = cache.burn_claimable_revenue();
guards::require_utilization_below_max(env, &cache);
guards::require_supply_for_debt(env, &cache);
```

`burn_claimable_revenue` (`contracts/pool/src/cache/shares.rs:54-75`) computes `amount = min(cash, floor(revenue * supply_index))` and subtracts the corresponding scaled shares from both `revenue` and `supplied`. There is no partial-claim input — the burn size is forced to the full claimable treasury whenever cash suffices.

`require_utilization_below_max` (`contracts/pool/src/guards.rs:19-34`) then computes `ceil(borrowed * borrow_index) / floor(supplied * supply_index)` and reverts with `CollateralError::UtilizationAboveMax` if it exceeds `params.max_utilization`. The check is skipped only when `max_utilization >= 1.0`, `supplied == 0`, or `borrowed == 0`.

Post-claim utilization is therefore `debt_value / (user_supply_value)` — revenue no longer counts in the denominator. Whenever `debt_value > max_utilization * user_supply_value`, the claim reverts no matter how large the accrued revenue is. Unlike a borrow (which checks utilization *before* drawing), this guard evaluates a state the protocol itself just created by removing revenue from supply. The pool test `test_claim_revenue_rejects_utilization_above_max_after_revenue_burn` (`contracts/pool/tests/flows.rs:1740-1758`) confirms the revert path exists.

Permissionless trigger path: `controller.claim_revenue(caller, assets)` → `markets::claim_revenue` → `claim_revenue_for_asset` → `pool.claim_revenue(hub_asset)` (`contracts/controller/src/markets.rs:129-209`, `contracts/pool/src/ops/revenue.rs:22-35`). Any signed caller hits it; no privileged gate is involved.

### Impact Explanation
Unclaimed protocol revenue — the reserve-factor fee plus supplier-reward shortfall booked every accrual step (`common/src/rates/simulate.rs:80-87`) — becomes permanently unclaimable for as long as the attacker's debt keeps `debt_value > max_utilization * user_supply_value`. This is theft-by-freeze of unclaimed yield in scope terms: revenue shares keep minting into `supplied` on every sync, but they can never be converted to cash and forwarded to the accumulator. The pool itself still operates, so the failure is silent rather than a full DoS — every accrual grows a treasury that accounting can never pay out.

### Likelihood Explanation
The precondition is attainable by any single funded account: supply enough collateral in one market, then `borrow` in the target market until debt approaches `max_utilization`. The attacker must then simply not repay; interest accrual on their own debt only *increases* `borrowed`, strengthening the block over time (interest raises debt value while user supply value grows slower under the reserve-factor split). Anyone calling `claim_revenue` — including keepers and the owner — gets `UtilizationAboveMax`. Sustaining the block costs the attacker borrow interest, but on a market with a low borrow rate or where the attacker is also the dominant supplier (collecting most of their own interest back), the cost is small. No privileged action, oracle manipulation, or third-party cooperation is required.

### Recommendation
Evaluate the utilization guard on the pre-burn state, or exclude revenue shares from the denominator consistently by checking utilization *before* `burn_claimable_revenue` runs. Alternatively, allow partial claims bounded by a target utilization (burn only enough revenue to keep `borrowed/supplied <= max_utilization`), so revenue can be drained progressively instead of reverting atomically.

### Proof of Concept
1. Admin configures market M with `max_utilization = 0.9` (a `< 1.0` cap; the guard at `guards.rs:20` is active).
2. ALICE supplies 100 units of M (user supply S = 100).
3. Attacker supplies collateral in another market and borrows 85 units of M. Utilization = 85/100 = 85% < 90%; borrow succeeds.
4. Time accrues; revenue shares R mint into `supplied`, so `supplied = 100 + R` and `cash` grows. Utilization *before* a claim is `85 / (100 + R)` — comfortably below max.
5. Any caller invokes `controller.claim_revenue(caller, [M])`. `burn_claimable_revenue` burns all R (cash covers it), leaving `supplied = 100`. `require_utilization_below_max` computes `85 / 100 = 85%`... — to force the revert, attacker sizes debt so `debt > 0.9 * user_supply`: with debt = 95 (still borrowable while revenue shares inflate the interim denominator, e.g. `supplied = 100 + R` with R ≥ 6 gives utilization `95/106 ≈ 89.6% < 90%`), the post-burn check computes `95/100 = 95% > 90%` and reverts with `UtilizationAboveMax`.
6. Interest accrual keeps raising `borrowed`; every subsequent `claim_revenue` call reverts identically. Revenue is unclaimable while the attacker leaves the debt open — matching the existing regression test's revert at `contracts/pool/tests/flows.rs:1757-1758`, reachable here through purely unprivileged borrow state.