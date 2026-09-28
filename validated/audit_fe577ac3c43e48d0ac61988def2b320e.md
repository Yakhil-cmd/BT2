### Title
`liquidate` applies the start-of-call liquidation bonus to the entire repayment even though the repayment traverses the HF bonus ramp — (File: contracts/controller/src/positions/liquidation/curve.rs)

### Summary
The liquidation bonus is selected once from the account's health factor *before* any repayment is applied, and that single BPS bonus is then charged on the whole repayment that moves HF from its current value all the way up to `liquidation_target_hf_wad`. Because the bonus curve ramps down as HF rises, a one-shot liquidation is priced at the worst (highest) bonus for every seized unit, whereas the same total repayment executed in slices would be repriced at progressively lower bonuses. This is the exact analog of the Zivoe M-8 class: an integral/curve is approximated by a single point evaluated at the favorable end of the traversal, so a single large action yields a different (here, larger) payout than the equivalent split action — and the difference is paid by the borrower as excess seized collateral.

### Finding Description
`build_liquidation_plan` snapshots the account risk totals once, storing `hf: totals.health_factor` in `LiquidationSnapshot` [1](#0-0) . `estimate_liquidation_amount` then calls `calculate_linear_bonus_with_target` exactly once on that pre-liquidation HF, and uses the resulting `bonus` to size the full `ideal` repayment toward `curve.target_hf` via `liquidation_at_target` [2](#0-1) . The curve itself ramps the bonus from `base` (at HF ≥ target) to `max` (at `hf_for_max_bonus`), so `bonus(hf_start)` is strictly greater than `bonus(hf)` for every intermediate HF the position passes through on the way to the target [3](#0-2) . Settlement then seizes `repay_usd × (1 + bonus)` pro rata, applying that single start-of-call bonus to the entire repayment [4](#0-3) .

Because each `liquidate` call recomputes HF fresh, splitting the same economic liquidation into N calls re-prices each later slice at a *higher* post-slice HF and therefore a *lower* curve bonus. Worked numbers (defaults `H = 1.1`, `K = 0.8`, `factor = 10000`, base 900 bps, `p = 0.78`, `D = 800`, `C = 1000`, `W = 780`, HF = 0.975): the single call repays `ideal ≈ 533.6` at `bonus = 1700` bps, seizing `533.6 × 1.17 ≈ 624.3`. If instead the liquidator repays ~267 in a first call (bonus 1700 bps → seizes ~312), the account's HF rises toward ~1.04, where the curve bonus is roughly 1100 bps; the second slice seizes materially less for the same debt retired. The monotonicity and ramp bounds are confirmed by `bonus_monotone_decreasing_in_hf` and `bonus_ramp_matches_closed_form_exactly` [5](#0-4) .

### Impact Explanation
The borrower loses more collateral than the curve intends for the marginal health restored: the full traversal from `hf_start` to `H` is charged at `bonus(hf_start)` instead of the path-integrated bonus. For accounts deep in the ramp (HF near `hf_for_max_bonus`), the spread between the applied bonus and the average traversal bonus can be thousands of BPS on the entire repaid amount — direct, permissionless transfer of borrower collateral value to the liquidator beyond what a correctly integrated curve would pay. This is theft of user funds under the impact definitions, reachable by any unprivileged address calling `controller.liquidate(liquidator, account_id, debt_payments, SeizeMode::Transfer)` on any account with `health_factor < 1e18` [6](#0-5) .

Caveat: this may be argued a deliberate design simplification (constant bonus per call, gas/budget-friendly), mirroring the Zivoe judges' downgrade rationale. If the intended semantics are "bonus at current HF," the discrepancy is inherent to any liquidation; the issue stands only if the curve is meant to price the marginal unit of restored health.

### Likelihood Explanation
Every liquidation of an account inside the ramp (`hf_for_max_bonus < HF < target_hf`) that repays more than a dust amount exercises this path — it is the default behavior, not an edge case. Liquidators are economically incentivized to submit one maximal `liquidate` rather than slices, since the single call maximizes the bonus applied. No privileged access, oracle manipulation, or special market state is required: any account that drifts below HF 1 inside the ramp is exposed.

### Recommendation
Price the traversal instead of the endpoint. Concretely, when `ideal` repayment moves HF from `hf_start` toward `target_hf`, either (a) split the bonus computation inside `estimate_liquidation_amount` into the portion below each relevant HF segment — analogous to the Zivoe recommendation — computing e.g. an average bonus over `[hf_start, min(hf_end, hf_for_max_bonus)]` plus the flat-max portion below `hf_for_max_bonus`; or (b) cap a single call's repayment at the amount that keeps post-liquidation HF within a fixed step, forcing re-pricing. At minimum, document that the bonus is intentionally evaluated at `hf_start` for the entire close, so borrowers and integrators can size partial liquidations accordingly.

### Proof of Concept
1. Open a position at max LTV in a spoke with default curve (`H = 1.1`, `K = 0.8`, `factor = 10000`), single collateral with threshold 7800 and bonus 900 (the documented worked example: `C = 1000`, `W = 780`, `D = 800`, HF = 0.975).
2. Call `get_liquidation_estimate(account_id, [(debt_asset, D)], SeizeMode::Transfer)` → `bonus_rate_bps = 1700`, `max_payment ≈ 533.62` USD.
3. Path A — single call: `liquidate(keeper, id, [(debt, 533.62)], Transfer)`. Seized value ≈ `533.62 × 1.17 ≈ 624.3` USD.
4. Path B — split: `liquidate` repaying ~267 USD (bonus 1700 → seize ~312), then a second `liquidate` on the now-healthier account; the second call recomputes HF ≈ 1.04 and applies a bonus of only ~1100 bps, seizing `x × 1.11` instead of `x × 1.17`.
5. Total collateral leaving the account in Path A exceeds Path B by `(1700 − ~1100) bps × ~267 USD ≈ 16` USD — excess seized from the borrower purely because the bonus was sampled at `hf_start` for the whole traversal, exactly the split-vs-single asymmetry of the source report.

### Citations

**File:** contracts/controller/src/positions/liquidation/plan.rs (L40-44)
```rust
    assert_with_error!(
        env,
        totals.health_factor < Wad::ONE,
        CollateralError::HealthFactorTooHigh
    );
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L54-60)
```rust
    let snap = LiquidationSnapshot {
        total_debt: totals.total_debt,
        total_collateral: totals.total_collateral,
        weighted_collateral: totals.weighted_collateral,
        proportion_seized,
        hf: totals.health_factor,
    };
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L46-55)
```rust
    fn bonus_scale(&self, env: &Env, hf: Wad, target: Wad) -> Wad {
        if target <= self.hf_for_max_bonus {
            Wad::ONE
        } else {
            target
                .checked_sub(env, hf)
                .div(env, target.checked_sub(env, self.hf_for_max_bonus))
                .min(Wad::ONE)
        }
    }
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L108-130)
```rust
    let scaled_bonus = calculate_linear_bonus_with_target(
        env,
        snap.hf,
        bounds.base,
        bounds.max,
        curve,
        curve.target_hf,
    );

    let bonus = match max_hf_preserving_bonus_bps(snap) {
        None => scaled_bonus,
        Some(_) if snap.total_collateral < snap.total_debt => {
            let one_plus_base = Wad::ONE.checked_add(env, bounds.base.to_wad(env));
            let backed = snap.total_collateral.div_floor(env, one_plus_base);
            return (backed.min(snap.total_debt), bounds.base);
        }
        Some(cap) if cap < bounds.base.raw() => {
            return (snap.total_debt, Bps::from(cap.max(0)));
        }
        Some(cap) => Bps::from(scaled_bonus.raw().min(cap)),
    };

    let ideal = liquidation_at_target(env, snap, bonus, curve.target_hf);
```

**File:** docs/reference/formulas.md (L225-231)
```markdown
let p = if C == 0 { 0 } else { half_up(W * WAD / C) };
let hf_bonus_cap_bps = floor(HF * BPS / p) - BPS; // only p > 0 and HF < WAD
let weighted_seizure = half_up(p * (WAD + b) / WAD);
let target_debt = half_up(H * D / WAD);
let backed_max = min(D, half_up(C * WAD / (WAD + b)));
let ideal = if H <= weighted_seizure || target_debt <= W { backed_max }
    else { min(backed_max, half_up((target_debt - W) * WAD / (H - weighted_seizure))) };
```

**File:** contracts/controller/tests/positions/liquidation_curve.rs (L606-622)
```rust
fn bonus_monotone_decreasing_in_hf() {
    let env = Env::default();
    let curve = LiquidationCurve::from_config(&default_spoke_config());
    let base = Bps::from(500i128);
    let max = Bps::from(2_500i128);
    let target = Wad::from(DEFAULT_LIQUIDATION_TARGET_HF_WAD);

    let mut prev = i128::MAX;
    for pct in (10..=102).step_by(2) {
        let hf = Wad::from(WAD * pct / 100);
        let b = calculate_linear_bonus_with_target(&env, hf, base, max, &curve, target).raw();
        assert!(
            b <= prev,
            "bonus must not increase as HF rises: hf={pct}% bonus={b} prev={prev}"
        );
        prev = b;
    }
```
