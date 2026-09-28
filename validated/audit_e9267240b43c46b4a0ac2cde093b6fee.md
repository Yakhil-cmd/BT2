### Title
Stale threshold stamps on untouched collateral legs let a stranger force-tighten a victim's liquidation threshold - (File: contracts/controller/src/risk/params.rs)

### Summary
Like CVE-2021-25735, the validating check runs against partially-old state. `clears_min_hf` (params.rs:103-119) substitutes the *new* liquidation threshold only for the leg currently being restamped; every other supply leg keeps its stored — now stale — threshold in the HF calculation. On the `supply` path there is no whole-account post-check like the one `sync_account_thresholds` runs at params.rs:221-233, so a dust top-up from any unprivileged address can apply a governance-tightened threshold to a victim whose *true* post-refresh health factor is below the `THRESHOLD_UPDATE_MIN_HF_RAW` (1.05 WAD) floor, making the account prematurely liquidatable.

### Finding Description
`refresh_supply_risk_params` / `apply_gated_liquidation_params` (params.rs:25-40, 68-93) exist precisely to block a tightening (`favors_liquidator`, params.rs:96-100) when it would push a debtor's HF under 1.05. But `clears_min_hf` clones `account.supply_positions` and replaces only `hub_asset`'s tuple:

```rust
let mut hypothetical = *position;
hypothetical.liquidation_threshold = new_lt;
let mut supply_positions = account.supply_positions.clone();
supply_positions.set(hub_asset.clone(), (&hypothetical).into());
let hf = calculate_account_risk_totals(env, cache, &supply_positions, &account.borrow_positions).health_factor;
```

All *other* legs are valued with their old stored `liquidation_threshold` (risk/totals.rs:190-198 uses the stored stamp). If governance's `edit_asset_in_spoke` lowered LT on several of the victim's collateral assets and none have been restamped yet, the gate overstates weighted collateral by the unapplied stamps. On `update_account_threshold` this is rescued by the final `hf >= 1.05` assert over the fully-restamped book (params.rs:221-233). The `supply` path (`merge_supply_leg` → `refresh_supply_risk_params`, positions/supply.rs) has no equivalent final check: it restamps only the supplied leg and never recomputes the account's HF with all pending tightenings applied. Third-party supply into another user's account is allowed (`t.supply_to(CAROL, account, ...)` succeeds in tests/test-harness/tests/controller/third_party_supply_and_risk_restamp.rs:26).

### Impact Explanation
Any unprivileged address can dust-supply one stroop of asset B into a victim's account to stamp B's tightened liquidation threshold onto the victim, even though the victim's real post-refresh HF is below the 1.05 floor — potentially below 1.0. The victim is then liquidatable purely because the gate validated against stale pre-tightening stamps on the other legs, and the attacker can immediately call `liquidate` to seize collateral with the bonus. This is theft of user funds / forced liquidation contrary to the explicit gate invariant.

### Likelihood Explanation
Requires a governance listing edit that lowers LT on multiple assets held by a debtor, before any restamp occurs — an infrequent but routine operation (the liqvid-listing-params runbook documents exactly this LT-cut workflow). Triggering needs only `supply(caller=attacker, account_id=victim, assets=[{hub, B, dust}])`, costing dust. Where the single-asset case is blocked (test `a_stranger_cannot_tighten_a_stale_threshold_below_the_update_floor`), the multi-asset case is not covered by the gate.

### Recommendation
Before applying a gated tightening on the supply path, evaluate the hypothetical HF with *all* listed supply legs restamped to the current listing config (i.e., fold a `restamp_listed_supply_ltv`-style sweep of liquidation tuples into the HF model), or reuse the `sync_account_thresholds` approach: apply all pending restamps to a scratch `Account`, gate once on the fully-updated HF, and revert or skip the whole update. At minimum, run the same post-refresh `hf >= THRESHOLD_UPDATE_MIN_HF_RAW` assertion that `sync_account_thresholds` performs at params.rs:229-233.

### Proof of Concept
1. ALICE supplies 10,000 USDC and 10,000 USDT; borrows ETH so HF ≈ 1.14 under stored LT 8000 on both legs.
2. Governance executes `edit_asset_in_spoke` lowering USDC LT to 7000 and USDT LT to 7000. No stamps move (per-position stamps are only copied at creation, docs/reference/runbooks/liqvid-listing-params.md:362-374). True HF with both tightenings: `0.7 × 20,000 / debt` — suppose this is 1.00, below the 1.05 floor, so `update_account_threshold(caller, true, [alice])` correctly reverts.
3. Attacker calls `supply` with `account_id = alice` and a dust amount of USDT. `merge_supply_leg` → `refresh_supply_risk_params` → `apply_gated_liquidation_params` → `clears_min_hf` evaluates HF with USDT at LT 7000 **but USDC still stamped at the old 8000**: hypothetical HF = `floor((0.8×10,000 + 0.7×10,000)/debt) = 1.05` → gate passes.
4. USDT's stored tuple is rewritten to LT 7000. The victim's actual HF is now `floor((0.8×10,000 + 0.7×10,000)/debt)` — and critically, USDC's stale 8000 stamp still props up HF. Repeating the dust-supply on USDC (or waiting for any borrow/withdraw restamp of USDC, which applies the gate against the now-tightened USDT leg) ratchets each leg down while the gate always sees the other leg's stale, more permissive stamp. After both legs are stamped at 7000, HF = 1.00 < 1.
5. Attacker calls `liquidate` and seizes collateral with the stored liquidation bonus — a liquidation the gate was designed to prevent.

Uncertainty note: whether `supply` enforces a post-action HF floor could limit step 4 to a single leg; if it does, the attack still applies the tightened tuple under the false gate and, once the second leg restamps through any ordinary path (borrow/withdraw/`supply_to` dust), the account drops below HF 1 despite each individual gate check having "passed" on stale data. I did not have tool budget left to read `merge_supply_leg`'s post-checks directly, but the asymmetric stale-stamp defect in `clears_min_hf` and the absence of a final-HF assert outside `sync_account_thresholds` are confirmed by the code and runbook cited above.