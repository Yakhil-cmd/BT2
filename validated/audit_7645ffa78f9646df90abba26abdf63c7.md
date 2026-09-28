### Title
Debt in a paused spoke asset can neither be repaid nor liquidated — a borrower who opens a single-asset borrow ahead of a listing pause becomes liquidation-immune while bad debt accrues - (File: contracts/controller/src/positions/liquidation/plan.rs)

### Summary
`build_liquidation_plan` enforces `FreezePolicy::AllowOnExit` on every repayment leg, and `AllowOnExit` reverts when the paid asset's spoke listing is `paused` (`SpokeAssetPaused`). Since a liquidator can only repay assets the account actually owes, an account whose entire debt book sits in a paused asset cannot be liquidated at all — the plan panics before the HF check and before any collateral can be seized. This mirrors the report's shape exactly: a governance "kill" of one market poisons the shared refresh/settlement path, so the position's real state can never be updated and the attacker keeps the extracted value.

### Finding Description
In `contracts/controller/src/positions/liquidation/plan.rs` lines 24–32, `build_liquidation_plan` iterates `raw_payments` and calls `enforce_spoke_asset_flags(..., FreezePolicy::AllowOnExit)` for each repaid debt asset, before the health-factor check and before seizure legs are built. In `contracts/controller/src/positions/mod.rs` lines 264–272, `AllowOnExit` asserts `!sa.paused` and panics with `SpokeError::SpokeAssetPaused`. `SeizureLeg` deliberately tolerates `paused`/`frozen` and rejects only `no_seize` (lines 129–141, ADR-0008 note: "applying `paused` to pro-rata seizure would block liquidation"), but that protection was applied only to the collateral side — the debt side still hard-reverts on `paused`.

The same `AllowOnExit` policy gates user-initiated exits, so while the listing is paused the debt also cannot be repaid through `repay`/`repay_debt_with_collateral`. The result is a symmetric wedge to the VotingEscrow bug: in the source bug, a killed bribe vault makes `_vote`/`poke` revert so the stale voting power can never be refreshed; here, a paused listing makes the liquidation plan and the repay path revert, so the borrower's deteriorating position can never be touched.

Exploit scenario:
1. Alice sees a queued/emergency governance operation that will set `paused = true` on spoke asset XYZ (e.g., `edit_asset_in_spoke` after an oracle or market incident — the same external trigger class as the source report's `killBribeVault`).
2. Alice supplies collateral, borrows XYZ to the maximum LTV, and holds no other debt assets.
3. Governance executes; XYZ is paused.
4. As XYZ (or the collateral) price moves against the protocol, Alice's HF falls below 1. Any liquidation attempt reverts at the repayment-leg flag check, regardless of how much the liquidator offers or which collateral they target. Alice also cannot be forced to repay, and voluntarily won't — she already holds the XYZ tokens.
5. Interest continues accruing on the unbacked debt until governance unpauses; if the pause is permanent or long-lived relative to the collateral's value decay, the debt becomes protocol bad debt settled only via `clean_bad_debt`/`recapitalize` at a loss to suppliers.

If the account also holds `no_seize` collateral legs, `SeizureLeg` gives a second independent revert, but the paused-debt path alone is sufficient when the debt book is single-asset.

### Impact Explanation
High, conditional. While paused, the account is fully liquidation-immune: `HealthFactorTooHigh`/`SpokeAssetPaused` reverts before any seizure, so collateral that belongs to suppliers cannot be recovered and borrow-index accrual deepens the shortfall. The acceptable impact classes are met: theft of user funds (Alice keeps borrowed assets worth more than her collateral), and protocol insolvency/bad debt that must be socialized through the supply-index write-down. This is weaker than the source bug in one respect — the freeze lasts only as long as the pause — but a pause on a broken asset is precisely the scenario where liquidation is most needed, so the window is exactly when losses accrue fastest.

### Likelihood Explanation
Low/Medium. Requires (a) governance pausing a spoke asset that has open borrows, and (b) an attacker positioning a single-asset debt beforehand, or an organic borrower who happens to hold one. Pause events do occur (depeg/exploit emergencies), and the borrow itself is fully permissionless — same likelihood profile as the source report.

### Recommendation
Differentiate "user-initiated exit" from "risk-reducing settlement" the same way the source report differentiates voting from poking. In `build_liquidation_plan`, the repayment leg should tolerate `paused` (a repayment reduces protocol exposure; there is no new exposure to gate), keeping `paused` enforcement only for `BlockOnEntry` paths and user withdrawals. Concretely, introduce a fourth policy (e.g., `FreezePolicy::LiquidationRepay`) that tolerates `paused` and `frozen`, or skip the flag check on repayment legs entirely and rely on `no_seize` for the collateral side. If keeping the revert is intentional, liquidations should at minimum skip-only-the-paused-leg rather than abort the whole plan when the account has other repayable debt.

### Proof of Concept
```text
1. Admin lists spoke asset XYZ (can_borrow = true) and collateral C.
2. Alice: supply(C, large), borrow(XYZ, max_ltv) — debt book = {XYZ} only.
3. Governance: edit_asset_in_spoke(XYZ, paused = true) executes.
4. Oracle: price of C falls (or XYZ debt accrues) until HF < 1.
   - calculate_account_risk_totals still values the position; is_liquidatable = true.
5. Liquidator calls liquidate(payments = [(XYZ, full_debt)]).
   - plan.rs L24-32: enforce_spoke_asset_flags(AllowOnExit) reads
     cached_spoke_asset(XYZ).paused == true
   - mod.rs L270-272: assert !sa.paused fails → SpokeAssetPaused → abort.
   - No collateral is seized; every retry reverts identically.
6. Alice's repay / repay_debt_with_collateral also revert (AllowOnExit),
   so the debt is frozen while the borrow index grows.
7. Protocol recovery requires unpause (re-exposing the market) or
   clean_bad_debt, which writes the loss into the supply index — a direct
   supplier loss caused by an unliquidatable position.
```

Caveat: if the design intent is that `paused` must also block liquidator repayments (e.g., to halt a compromised token's flows entirely), this is a documented ADR trade-off and should be downgraded; the code comments only justify sparing `paused` on the *seizure* side and do not address the repayment leg.