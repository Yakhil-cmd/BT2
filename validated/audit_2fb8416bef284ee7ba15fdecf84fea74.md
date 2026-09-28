### Title
Supplier can front-run `clean_bad_debt` / `force_socialize_bad_debt` to withdraw at the pre-write-down supply index, concentrating the socialized loss on remaining suppliers - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
`clean_bad_debt` is permissionless and `force_socialize_bad_debt` is a scheduled governance operation with a known execution window. Both write the bad debt down against the market's supply index, diluting every supplier. Any supplier who observes the pending cleanup transaction can submit `withdraw` first and be paid `floor(scaled_amount * old_supply_index)` in full from pool cash, escaping the write-down entirely and leaving the loss — and the drained cash — to the suppliers who did not exit.

### Finding Description
Bad-debt socialization lowers the affected `(hub, token)` market's `supply_index`: `new_supply_index = floor(old_index * (total_supply - bad_debt) / total_supply)`, clamped at `RAY/1000` (`apply_bad_debt_to_supply_index`, formulas.md). Every supplier's claim is `scaled_amount * supply_index`, so the write-down is pro-rata — but only over the shares that exist at the moment the cleanup executes.

`process_clean_bad_debt` (`contracts/controller/src/positions/liquidation/mod.rs:196-200`) requires only `caller.require_auth()` and `require_not_flash_loaning` — anyone can call it as soon as `D > C` and `C <= $5` hold. `withdraw` on the controller is permissionless for a debt-free supplier and pays out at the *current* index via `resolve_withdrawal` (`common/src/rates/scaling.rs:105-121`), gated only by `require_reserves` (cash), `require_utilization_below_max`, and `require_supply_for_debt` (`contracts/pool/src/ops/withdraw.rs:111-119`). There is no sequencing or lock tying pending bad-debt recognition to exits; an under-backed market still permits withdrawal.

So the ordering race is real: the cleanup transaction is visible in-flight (or, for `force_socialize_bad_debt`, publicly scheduled on the Sensitive delay tier), and a supplier's `withdraw` lands at the pre-write-down index while the cleanup's write-down then falls on a smaller `supplied` base.

### Impact Explanation
- Suppliers who do not front-run absorb a larger per-share loss than the pro-rata share intended: the write-down formula divides the bad debt over the *remaining* `total_supply`, so each early exit raises the percentage written off for those left.
- The exiting supplier takes real cash out; after the write-down (and especially at the `RAY/1000` floor, which leaves stranded claims), remaining suppliers can hold claims exceeding pool cash, leaving funds effectively frozen until repayment inflows or `recapitalize` — the contract even documents that the floor leaves residual claims without backing. This is theft/unfair transfer of the socialized loss plus temporary freezing of remaining suppliers' funds.

### Likelihood Explanation
- `clean_bad_debt` is callable by any address the instant the dust gate opens, so a rational keeper executes it immediately — giving suppliers a mempool-level race window on every qualifying liquidation aftermath.
- `force_socialize_bad_debt` goes through governance on a delayed tier, so its execution is publicly predictable well in advance; racing it requires no mempool sophistication at all.
- The only mitigations are circumstantial: `require_utilization_below_max` blocks normal withdrawals only once utilization is at the cap, and `require_reserves` only once cash is exhausted — the first movers always get out.
- Requires the attacker to already be a supplier in the affected market, so this is a real-but-conditional exit race: Medium.

### Recommendation
Recognize bad debt earlier so exits cannot beat the write-down, e.g.:
- Mark markets with pending socializable bad debt (a "bad-debt-pending" flag set by the liquidate/cleanup path or by a permissionless poke) that blocks or reprices non-liquidation withdrawals at the post-write-down index until cleanup runs; or
- Perform bad-debt write-down lazily inside `withdraw`/`supply` — before resolving the withdrawal, check whether any uncleaned insolvent account qualifies for the market and apply the index reduction first; or
- At minimum, run `clean_bad_debt` for eligible accounts inside the `liquidate` flow (already partially done via post-liquidation cleanup) and document that supplier exits ahead of `force_socialize_bad_debt` should be gated.

### Proof of Concept
1. Bob supplies 100 ETH into hub-1; Alice's account becomes insolvent with ETH debt and ≤$5 collateral after a price move (`test_keeper_clean_bad_debt_decreases_supply_index` fixture shape).
2. Dave, also an ETH supplier (or Bob himself), observes the incoming `clean_bad_debt(account_id)` transaction — or the scheduled `ForceSocializeBadDebt` governance operation.
3. Dave calls `withdraw(caller=Dave, account_id, hub_asset=(hub1, ETH), amount=0)` (withdraw-all). `resolve_withdrawal` pays `floor(Dave_scaled * old_supply_index)` in full; `require_reserves` passes because cash is still present; `require_backed_market` does not run on exits.
4. `clean_bad_debt` lands next: `apply_bad_debt_to_supply_index` writes `new_index = floor(old_index * (total_supply - bad_debt) / total_supply)` over a `total_supply` that no longer includes Dave's shares — remaining suppliers' per-share loss is strictly larger, and if the write-down hits the `RAY/1000` floor or cash was drained, their claims exceed backing until `recapitalize`.

Net effect: identical to the RFP report's class — an actor changes their committed position in the same window as a pending settling transaction, escaping the term (here, the loss allocation) the protocol was about to apply.