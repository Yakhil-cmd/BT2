### Title
Withdraw-path HF gate evaluates the pre-withdrawal collateral, so a liquidator-favorable risk tuple is applied to a position whose real post-withdrawal HF is below the 1.05 floor - (File: contracts/controller/src/positions/supply.rs)

### Summary
The analog of CVE-2021-29984's "reordering makes an object incorrectly considered" is a sequencing bug in `merge_withdraw_leg`: the position's `scaled_amount` is overwritten with the post-withdrawal value locally, but the write-back into `account.supply_positions` is deferred until *after* the gated liquidation-parameter refresh runs. The gate's health-factor check (`clears_min_hf` → `calculate_account_risk_totals`) therefore reads the stale, larger pre-withdrawal collateral for the leg being refreshed, and applies an adverse (liquidator-favorable) tuple that the 1.05 health-factor floor was designed to withhold.

### Finding Description
`merge_withdraw_leg` in `contracts/controller/src/positions/supply.rs:328-377` runs in this order:

1. `position.scaled_amount = outcome.new_scaled` (line 343) — the reduced, post-withdrawal share balance is written only into the local `position` copy.
2. `refresh_supply_risk_params(..., &mut position, ..., RiskRefreshScope::FullTuple)` (lines 356-367) — calls `apply_gated_liquidation_params` (`contracts/controller/src/risk/params.rs:68-93`), which for a debt-bearing account and a liquidator-favorable config change calls `clears_min_hf` (`params.rs:103-119`). `clears_min_hf` clones `account.supply_positions` and overwrites only the *tuple* (`hypothetical.liquidation_threshold = new_lt`), not the scaled amount. The map it clones still holds the **old** `scaled_amount` for this `hub_asset`, because `update_or_remove_supply_position` (line 369) has not run yet.
3. `update_or_remove_supply_position(account, hub_asset, &position)` (line 369) — the reduced balance is persisted only now, after the gate already decided.

So the gate computes `HF >= THRESHOLD_UPDATE_MIN_HF_RAW` (1.05) using the pre-withdrawal collateral for the leg whose collateral is being removed. On a partial withdrawal that leaves the account's true HF in the `(1.0, 1.05)` band, the gate wrongly concludes the account can absorb the adverse change and stamps in the new `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` (`params.rs:90-92`).

The sibling path `merge_supply_leg` (lines 288-299) deliberately refreshes *before* applying the new shares, which the docs acknowledge ("the gate calculates the HF before the new supply adds to the collateral"); that ordering is conservative. The withdraw path has the opposite defect: the balance reduction is already decided but invisible to the gate.

The post-call solvency gate (`enforce_post_pool_solvency`, called from `process_withdraw` at `supply.rs:158`) bounds the bug: if applying a *lowered threshold* drops HF below 1.0 the whole call reverts. The harm survives through the components that do not enter HF — a raised `liquidation_bonus` and a lowered `liquidation_fees` — which are stamped onto the position even though the real post-withdrawal HF is below the 1.05 floor the gate enforces for exactly this situation (`tests/test-harness/tests/controller/keeper.rs:301-341` pins the intended behavior for `update_account_threshold`).

### Impact Explanation
Once the adverse tuple is stamped, it persists on the position and is used by every subsequent liquidation (`get_account_bonus_params` reads the stored bonus and fee). A liquidator — any unprivileged address — then seizes collateral with a bonus higher than protocol policy intended for an account at that health, and pays a lower liquidation fee to the protocol. The excess comes directly out of the withdrawing user's collateral: theft of user funds, executed by the permissionless `liquidate` entrypoint. The victim's own routine partial withdraw is the trigger; no further victim cooperation is needed once the tuple is restamped.

### Likelihood Explanation
Requires two preconditions: (a) a listing edit that raises the liquidation bonus or lowers the liquidation fee (a routine governance `editAssetInSpoke`, e.g. the documented LT/bonus retunes in `docs/explanation/decisions-r23.md`), and (b) the account owner partially withdrawing the affected collateral while the post-withdrawal HF lands in `(1.0, 1.05)` — a band roughly 5% wide that leveraged accounts routinely enter when deleveraging-by-withdrawal. The attacker cannot force the victim's withdraw, but no attacker action is needed at all: any user withdrawing in the window stamps the adverse tuple on themselves, and the next liquidator collects the inflated bonus. Rated Medium: real loss of user funds, but gated on a coincident adverse listing change and a narrow HF band.

### Recommendation
In `merge_withdraw_leg`, persist the mutated position into `account.supply_positions` *before* calling `refresh_supply_risk_params` (i.e., move `update_or_remove_supply_position` ahead of the `may_restamp` block, or pass a hypothetical `supply_positions` map with `new_scaled` installed to `clears_min_hf`, the same way `clears_min_hf` already substitutes the hypothetical threshold). Then re-record the event with the post-refresh tuple. Add a regression test: account with debt, listing edit that raises `liquidation_bonus`, partial withdraw leaving true HF ≈ 1.02 — assert the stored bonus is unchanged.

### Proof of Concept
1. Market USDC listed with `liquidation_bonus = 500`; governance edits the spoke listing to `liquidation_bonus = 1000` (liquidator-favorable → gated).
2. Alice: supplies USDC collateral, borrows ETH so that HF = 1.10. No withdraw → `update_account_threshold(true)` on her account would revert at `HealthFactorTooLow`, so her stored bonus stays 500.
3. Alice calls `withdraw(USDC, amount)` where `amount` is chosen so her true post-withdrawal HF = 1.03. The pool pays out; `merge_withdraw_leg` sets `position.scaled_amount` to the reduced value locally, but `clears_min_hf` computes HF on `account.supply_positions` still holding the pre-withdrawal balance → sees HF ≈ 1.10-ish contribution from the stale leg → gate passes → `position.liquidation_bonus = 1000` is stamped.
4. `enforce_post_pool_solvency` sees HF 1.03 ≥ 1.0 → call succeeds. Alice's position now carries `liquidation_bonus = 1000` despite the design floor of 1.05.
5. Price drifts so HF < 1; a liquidator calls `liquidate` and receives the 1000-BPS bonus instead of 500-BPS — excess paid from Alice's collateral.

Note on confidence: the ordering defect is directly visible in the code (the deferred write-back at `supply.rs:369` versus the gate call at `supply.rs:356-367` and the stale-map clone at `params.rs:113-114`). What I could not fully verify is whether `enforce_post_pool_solvency` or a later gate re-checks and reverts on the stamped bonus/fee components — the solvency check only constrains LTV-weighted collateral and HF, which bonus/fee do not affect, so the stamp should persist.