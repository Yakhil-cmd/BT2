### Title
Crafted debt size in the whole-unit margin band makes a sub-3-decimal collateral position unliquidatable — every `liquidate` offer reverts (DoS) - ([File: contracts/controller/src/positions/liquidation/math.rs])

### Summary
`whole_unit_repayment` contains a gap between its two quote-raising rules: when an account's only supply leg is a sub-3-decimal asset holding at least one whole unit, and the risk-valued debt `D` falls in the narrow band `floor(U / (1 + b)) - R < D <= ceil((U + m) / (1 + b))`, neither the full-close rule nor the one-unit-sale rule applies, so the raw curve quote stands. Since the seizure for such a leg rounds to whole token units and the curve quote backs less than one unit, the plan seizes nothing and `liquidate` reverts with `InvalidPayments` — for every possible offer size. An attacker can open a borrow position sized into this band and hold an undercollateralized (HF < 1) account that no liquidator can touch until interest accrual or a price move drifts `D` out of the band.

### Finding Description
For a solvent account (`C >= D`) whose single supply leg is below `MIN_BORROWABLE_ASSET_DECIMALS` (3) and holds `>= 1` whole unit, `normalize_repayment_plan` calls `whole_unit_repayment` to adjust the curve quote [1](#0-0) . Inside `whole_unit_repayment`:

- Rule 1 (full close) fires only when `unit_at_bonus = floor(U / (1 + b)) >= D + R`, where `R` is one base unit of each debt leg in USD [2](#0-1) .
- Rule 2 (raise to one-unit repayment) is only *returned* when `unit_repayment = ceil((U + m) / (1 + b)) < D`; when `unit_repayment >= D` the function returns the unraised curve quote [3](#0-2) .

So for `floor(U/(1+b)) - R < D <= ceil((U+m)/(1+b))` the quote stays at `ideal`, which by construction backs strictly less than one whole unit. The seizure leg for a sub-3-decimal asset then rounds down to zero units, the unbacked repayment is released, the seized set is empty, and `build_liquidation_plan`/`plan.validate` reverts with `InvalidPayments` [4](#0-3) . The protocol's own documentation confirms "every offer reverts until accrual or a price move ends that state" [5](#0-4) . A raised quote is a ceiling, not a floor, so no smaller or larger offer escapes the revert [6](#0-5) .

The band is reachable by a single unprivileged address: `supply` a sub-3-decimal listed collateral, `borrow` a debt amount tuned (in arbitrary base-unit precision) into the band at a healthy HF, then wait for a small price move or accrual to push HF below 1 while `D` remains inside the band.

### Impact Explanation
Temporary freezing of funds / liquidation DoS. While the debt sits in the band, the account is provably unhealthy (`HF < 1`) yet every `liquidate` call aborts, so the position cannot be de-risked. During the freeze the debt keeps accruing interest and the collateral can keep falling, so the account can transition from barely-unhealthy to insolvent without any liquidator being able to act. If it lands insolvent with `C <= $5` the residue is socialized via `clean_bad_debt`, transferring the loss to the market's suppliers through the supply-index write-down — i.e., the DoS can convert into realized protocol insolvency. `clean_bad_debt` itself is gated on `D > C`, so it cannot preempt the band while the account is still solvent.

### Likelihood Explanation
The band is narrow — roughly `R + m/(1+b)` wide, on the order of 10^-6 of one unit's USD value plus one base unit per debt leg — but `D` is not adversary-luck-dependent: the borrower chooses the borrow amount in base units and can place it exactly in the band at open time, then wait for the small price/accrual drift that drops `HF < 1`. Collateral price volatility or ordinary interest accrual eventually moves `D` out of the band's top edge, so the freeze is temporary rather than permanent; duration depends on accrual rate versus band width. Requires a listed sub-3-decimal collateral asset (e.g., the 0–2 decimal RWA-style listings the codebase explicitly supports).

### Recommendation
Close the gap in `whole_unit_repayment`: when `unit_repayment >= snap.total_debt` but rule 1 did not fire (i.e., `unit_at_bonus < D + R`), return `snap.total_debt` (full close, seizing one unit) instead of the raw curve quote. Equivalently, fold rule 2's condition into rule 1's boundary so the decision is monotone in `D` — any `D` that one unit at `1 + b` can repay should quote a full close. Alternatively, promote the quote to `D` whenever the unadjusted quote would seize zero whole units and the leg holds at least one, ensuring a sub-3-decimal account below `HF = 1` is always liquidatable.

### Proof of Concept
1. Governance lists collateral asset `X` with `asset_decimals = 0`, unit price `U ≈ $850`, liquidation threshold `LT`, in a hub where the attacker also borrows 7-decimal USDC.
2. Attacker `supply`s `k` whole units of `X` (e.g., 2 units) and `borrow`s USDC such that risk-valued debt `D` satisfies `floor(U/(1+b)) - R < D <= ceil((U+m)/(1+b))` — the borrow amount is free-precision, so this is deterministic. At open, `C >= D` and `HF >= 1`.
3. Price of `X` drifts down (or debt accrues) so `HF < 1` while `D` remains in the band.
4. Any liquidator calls `liquidate(caller, account_id, payments, seize_mode)`. `estimate_liquidation_amount` returns a curve quote backing less than one unit; `whole_unit_repayment` hits neither rule 1 (`unit_at_bonus < D + R`) nor rule 2 (`unit_repayment >= D` → returns `quote_usd`) [7](#0-6) .
5. The seizure leg rounds to zero whole units; `plan.validate` reverts `InvalidPayments` for every offer size — confirmed by the documented exception in `docs/reference/formulas.md` ("every offer reverts until accrual or a price move ends that state") [5](#0-4) .
6. The debt remains unseizable while it accrues; if `C` drops below `D` and under $5, a keeper's `clean_bad_debt` writes the loss down against the market's `supply_index` [8](#0-7) .

### Citations

**File:** contracts/controller/src/positions/liquidation/math.rs (L186-192)
```rust
    let (curve_repayment_usd, bonus) = estimate_liquidation_amount(env, snap, bonus_bounds, curve);
    let insolvent = snap.total_collateral < snap.total_debt;
    let ideal_repayment_usd = if insolvent || curve_repayment_usd >= snap.total_debt {
        curve_repayment_usd
    } else {
        whole_unit_repayment(env, account, snap, curve_repayment_usd, bonus, cache)
    };
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L275-290)
```rust
    let full_close_ceiling = snap
        .total_debt
        .checked_add(env, one_unit_per_debt_leg_usd(env, account, cache));
    if unit_at_bonus >= full_close_ceiling {
        return snap.total_debt;
    }
    let unit_repayment = Wad::from(mul_div_ceil(
        env,
        unit_with_margin.raw(),
        Wad::ONE.raw(),
        one_plus_bonus.raw(),
    ));
    if unit_repayment >= snap.total_debt {
        return quote_usd;
    }
    unit_repayment
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L73-96)
```rust
    let (seized_collaterals, unbacked_usd) =
        calculate_seized_collateral(env, account, totals.total_collateral, &repayment, cache);
    release_unbacked_repayment(env, &mut repayment, unbacked_usd);
    if unbacked_usd > Wad::ZERO && seized_collaterals.is_empty() {
        let repay_usd = repayment.repay_usd;
        release_unbacked_repayment(env, &mut repayment, repay_usd);
    }

    for entry in seized_collaterals.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &entry.hub_asset,
            FreezePolicy::SeizureLeg,
        );
    }

    let plan = LiquidationPlan {
        repayment,
        seized: seized_collaterals,
    };
    plan.validate(env);
    plan
```

**File:** docs/reference/formulas.md (L296-300)
```markdown
The raised quote is a ceiling, not a floor. A smaller offer is not raised. An
offer that backs less than one whole unit seizes nothing and reverts with
`InvalidPayments` (16). An offer between `U / (1 + b)` and the raised quote
still takes one unit. Size offers for such a leg from
`get_liquidation_estimate`, not from the curve formula.
```

**File:** docs/reference/formulas.md (L305-308)
```markdown
one-unit sale or by a full close. There is one exception. While
`floor(U / (1 + b)) - R < D <= ceil((U + m) / (1 + b))`, neither rule 1 nor
rule 2 applies. If the curve quote then backs less than one unit, every offer
reverts until accrual or a price move ends that state.
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L222-237)
```rust
    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```
