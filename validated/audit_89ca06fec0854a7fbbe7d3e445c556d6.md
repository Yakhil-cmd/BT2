### Title
Sub-3-decimal single-collateral accounts can enter a permanently unliquidatable and un-socializable bad-debt state - (File: contracts/controller/src/positions/liquidation/math.rs)

### Summary
Like CVE-2021-35577 (a reachable input shape that crashes/stalls the server), a borrower can craft an account shape that makes every `liquidate` call revert while `clean_bad_debt` can never open, so the position's debt accrues unbounded until it is pure protocol loss. The band is created by `whole_unit_repayment` in `contracts/controller/src/positions/liquidation/math.rs` combined with the `$5` dust gate in `is_socializable_bad_debt`.

### Finding Description
For a solvent account whose only supply leg is below `MIN_BORROWABLE_ASSET_DECIMALS` (3), `whole_unit_repayment` only rescues liquidations in two cases [1](#0-0) :

- Rule 1: `unit_at_bonus >= D + R` → full close.
- Rule 2: `quote*(1+b) < U + margin` and `raised < D` → seize one unit.

When `unit_at_bonus - R < D` and the curve quote backs less than one whole unit, neither rule fires and every `liquidate` offer reverts (`InvalidPayments` / zero seizure), as documented in `docs/reference/formulas.md` ("every offer reverts until accrual or a price move ends that state") [2](#0-1) .

The escape hatch fails when one whole unit `U` of the collateral token is worth more than the $5 `BAD_DEBT_USD_THRESHOLD`:

1. Interest accrual only *grows* `D`. Once `D > raised`, rule 2's `raised < D` guard fails permanently; rule 1 requires `D <= unit_at_bonus - R`, so growth pushes the account deeper into the dead band rather than out of it. If the curve quote still backs less than one unit (true whenever `U` is large relative to `D`'s liquidation range), liquidation is permanently bricked.
2. `clean_bad_debt` requires `total_collateral <= 5 WAD` [3](#0-2) . The account's collateral is at least one indivisible whole unit worth `U > $5`, and partial seizure is impossible, so collateral can never fall under the dust gate. The permissionless cleanup can never open.
3. `repay` is only reachable by the borrower, who has no incentive.

### Impact Explanation
Permanent protocol insolvency: the attacker's debt accrues interest indefinitely with no liquidation or socialization path. Only the owner-gated `force_socialize_bad_debt` can clean it, meaning unprivileged-market bad debt silently accumulates against suppliers of the borrowed markets — a Medium-severity availability/solvency analog to the MySQL hang.

### Likelihood Explanation
Fully reachable by one unprivileged address: supply a <3-decimal collateral whose unit value exceeds $5 (e.g., a 2-decimal token at ≥$6/unit), borrow into the band `unit_at_bonus - R < D <= raised` such that the curve quote backs < 1 unit, then let the position drift below HF 1 (borrow interest alone suffices since the band is narrow and `D` grows into `D > raised`). No privileged action, oracle manipulation, or timing is required.

### Recommendation
When `whole_unit_repayment` cannot raise the quote and the quote backs less than one unit, either (a) promote the quote to the repayment backing one whole unit unconditionally (drop the `raised < D` guard, capping at `D` instead of reverting), or (b) treat such accounts as socializable by relaxing the dust gate when the only collateral is a single indivisible unit below 3 decimals.

### Proof of Concept
1. Governance lists token `LOW2` (2 decimals, unit price $1,000) as collateral-only; attacker supplies 2 whole units ($2,000 collateral).
2. Attacker borrows USDC such that after `HF` crosses 1 via accrual/price, `D` satisfies `floor(U/(1+b)) - R < D <= ceil((U+m)/(1+b))` and `quote*(1+b) < U + m` — i.e., `D` in roughly `($1,000/(1+b) - R, $1,000/(1+b)]`.
3. Any `liquidate` call reverts: `whole_unit_repayment` returns the unraised quote, seizure rounds to zero whole units, plan validation fails [4](#0-3) .
4. `clean_bad_debt` reverts with `CannotCleanBadDebt` because collateral is $2,000 > $5 [5](#0-4) .
5. Accrual pushes `D` above `raised`, making the state permanent; the USDC market accumulates unbounded bad debt until governance force-socializes.

### Citations

**File:** contracts/controller/src/positions/liquidation/math.rs (L235-260)
```rust
fn whole_unit_repayment(
    env: &Env,
    account: &Account,
    snap: &LiquidationSnapshot,
    quote_usd: Wad,
    bonus: Bps,
    cache: &mut Context,
) -> Wad {
    if account.supply_positions.len() != 1 {
        return quote_usd;
    }
    let Some((hub_asset, position)) = iter_typed_positions(&account.supply_positions).next() else {
        return quote_usd;
    };
    let feed = cache.cached_price(&hub_asset.asset);
    if feed.asset_decimals >= MIN_BORROWABLE_ASSET_DECIMALS {
        return quote_usd;
    }
    let supply_index = cache.cached_market_index(&hub_asset).supply_index;
    let held_units = position
        .scaled_amount
        .mul(env, supply_index)
        .to_asset_floor(env, feed.asset_decimals);
    if held_units < 1 {
        return quote_usd;
    }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L269-290)
```rust
    let unit_at_bonus = Wad::from(mul_div_floor(
        env,
        unit_usd.raw(),
        Wad::ONE.raw(),
        one_plus_bonus.raw(),
    ));
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

**File:** contracts/controller/src/positions/liquidation/plan.rs (L63-96)
```rust
    let mut repayment = normalize_repayment_plan(
        env,
        account,
        raw_payments,
        &snap,
        bonus_bounds,
        &curve,
        cache,
    );

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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-237)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```
