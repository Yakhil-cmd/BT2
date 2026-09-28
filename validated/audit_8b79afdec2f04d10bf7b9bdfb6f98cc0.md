### Title
Permissionless `repay` can pin an underwater single-collateral sub-3-decimal account inside the unliquidatable whole-unit band, freezing the collateral — (`File: contracts/controller/src/positions/liquidation/math.rs`)

### Summary
`whole_unit_repayment` defines a narrow debt band in which neither the full-close rule nor the one-unit-sale rule applies; while the debt sits in that band and the curve quote backs less than one whole collateral unit, every `liquidate` call reverts with `InvalidPayments`. Because `repay` is permissionless and reduces debt in arbitrarily small increments, any unprivileged address can drive a victim's debt into that band and keep it there, leaving the account permanently below HF = 1 yet impossible to liquidate.

### Finding Description
The kernel CVE is a boundary/alignment flaw: a payload that violates size/alignment assumptions falls into an unhandled gap and crashes the system. The analog here is a rounding-boundary gap in the liquidation whole-unit rules.

In `normalize_repayment_plan`, a solvent partial plan delegates to `whole_unit_repayment` [1](#0-0) . That helper applies only when the account's sole supply position is a below-`MIN_BORROWABLE_ASSET_DECIMALS` asset holding at least one whole unit [2](#0-1) . It computes `unit_at_bonus = floor(U / (1 + b))` and the full-close ceiling `D + R` (one base unit per debt leg) [3](#0-2) , and the raised quote `ceil((U + m) / (1 + b))` [4](#0-3) .

The documented consequence is the gap: while `floor(U/(1+b)) − R < D <= ceil((U+m)/(1+b))`, neither rule fires, and if the curve quote then backs less than one unit, "every offer reverts until accrual or a price move ends that state" [5](#0-4) . An offer backing less than one unit seizes nothing and reverts `InvalidPayments` [6](#0-5) .

The exploitable piece is that `repay` is permissionless: `process_repay` only calls `require_authorized_caller` on the payer and then applies measured payments against the target's debt [7](#0-6) ; "anyone may repay any account's debt" [8](#0-7) . Debt reduction is granular to base units, so an attacker can repay a victim's debt down into the band from above, and whenever interest accrual lifts `D` above the band's top edge, repay a few more units to drop it back in — indefinitely.

### Impact Explanation
Temporary freezing of funds sustained for as long as the attacker keeps paying. While the account sits in the band with HF < 1:

- Every `liquidate` reverts (`InvalidPayments`), so neither `Transfer` nor `Credit` seizure can execute; the protocol cannot deleverage the position and the victim's collateral cannot be recovered through liquidation.
- The victim cannot `withdraw` (owner-gated withdrawal re-proves solvency), so the collateral is locked.
- If the account drifts insolvent, `clean_bad_debt` still works only once residual collateral is ≤ the $5 dust threshold, so this does not even reach the bad-debt escape hatch while collateral is above dust.

The attacker pays small debt-repayment amounts to sustain the pin; the frozen value is the victim's entire collateral position.

### Likelihood Explanation
Requires a listed market with `asset_decimals < MIN_BORROWABLE_ASSET_DECIMALS` (0–2 decimals, e.g. the RWA/share-class listings the code is clearly built around) as the victim's only supply position, and HF < 1. Both are reachable by ordinary positions; the attacker needs only a small token budget for periodic repayments. Medium: real and reachable, but impact is temporary (bounded by attacker spend and price moves) and confined to a narrow collateral class.

### Recommendation
Close the gap in `whole_unit_repayment`: when `quote` backs less than one unit and neither rule 1 nor rule 2 fires, either promote the quote to the minimum that backs one unit anyway (allowing `unit_repayment >= snap.total_debt` to become a full close) or clamp the quote to `snap.total_debt`. Alternatively, bound how close third-party `repay` may push a debt toward the band — e.g., reject repayments that leave a sub-3-decimal-only-collateral account unhealthy but inside the gap — though the cleaner fix is removing the unreachable-quote state itself.

### Proof of Concept
1. Victim supplies a 0–2 decimal asset (sole supply position, ≥1 whole unit held) and borrows up to just under the liquidation threshold.
2. Price move pushes HF < 1.
3. Attacker calls permissionless `repay(caller, account_id, payments)` sized so remaining debt `D` satisfies `floor(U/(1+b)) − R < D <= ceil((U+m)/(1+b))` with the curve quote backing less than one unit.
4. Every `liquidate` and `get_liquidation_estimate`-sized offer reverts `InvalidPayments`; `zdc_sub_unit_liquidation_reverts_without_charging` demonstrates the revert path [9](#0-8) .
5. On each index accrual that lifts `D` above the band edge, attacker repays the delta in base units to re-enter the band, sustaining the freeze.

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

**File:** contracts/controller/src/positions/liquidation/math.rs (L243-258)
```rust
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
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L269-279)
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
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L281-289)
```rust
    let unit_repayment = Wad::from(mul_div_ceil(
        env,
        unit_with_margin.raw(),
        Wad::ONE.raw(),
        one_plus_bonus.raw(),
    ));
    if unit_repayment >= snap.total_debt {
        return quote_usd;
    }
```

**File:** docs/reference/invariants.md (L426-437)
```markdown
solvent account whose leg holds a whole unit, the partial quote can change.
When one unit's value divided by `1 + bonus` covers the whole debt plus one base
unit of each debt leg, the quote becomes the whole debt and the leg rounds up to
one unit. That full close can pay the liquidator more than the quoted bonus.
Otherwise, when the quote seizes less than one unit plus a `1e-6` margin, it
rises to the repayment that backs one unit plus the margin, if that repayment
is below the whole debt. The seizure then refunds the margin, rounded down to
whole debt-token units. Thus such an account stays liquidatable below `HF = 1`, by a one-unit
sale or by a full close. The exception is a debt in the narrow band where
neither change applies: if the curve quote backs less than one unit, every
offer reverts until accrual or a price move ends that state. See
[whole-unit legs](formulas.md#bonus-and-target-repayment).
```

**File:** docs/reference/formulas.md (L296-300)
```markdown
The raised quote is a ceiling, not a floor. A smaller offer is not raised. An
offer that backs less than one whole unit seizes nothing and reverts with
`InvalidPayments` (16). An offer between `U / (1 + b)` and the raised quote
still takes one unit. Size offers for such a leg from
`get_liquidation_estimate`, not from the curve formula.
```

**File:** contracts/controller/src/positions/debt.rs (L69-91)
```rust
pub(crate) fn process_repay(
    env: &Env,
    caller: &Address,
    account_id: u64,
    payments_in: &Vec<HubPayment>,
) {
    validation::require_authorized_caller(env, caller);

    let aggregated = payments::aggregate_positive_payments(env, payments_in);
    let mut account = storage::get_account_borrow_only(env, account_id);
    let mut cache = Context::new(env);

    settle_repay(env, &mut account, caller, &aggregated, &mut cache);

    finalize_position_flow(
        env,
        account_id,
        &account,
        &mut cache,
        PositionSides::Debt,
        false,
    );
}
```

**File:** contracts/controller/README.md (L34-36)
```markdown
  entrypoints are permissionless instead: anyone may `repay` any account's
  debt, `liquidate` an account whose health factor is below one (including the
  account's own owner), and `clean_bad_debt` on an insolvent account once its
```

**File:** tests/test-harness/tests/controller/zero_decimal_collateral.rs (L510-525)
```rust
fn zdc_sub_unit_liquidation_reverts_without_charging() {
    let mut z = setup(nav(1_000));
    let id = open(&mut z, "alice", 10, 1_000, 5_800);
    z.t.set_price(LIQ, nav(800));
    let debt = z.debt_raw(id);
    let est = z.estimate(id, usdc_raw(1), SeizeMode::Transfer);
    assert_eq!(est.seized_collaterals.len(), 0);
    assert_eq!(est.max_payment_wad, 0, "no payment is quoted");

    let err = z
        .liquidate(id, usdc_raw(1), SeizeMode::Transfer)
        .unwrap_err();
    assert_eq!(err, Error::from_contract_error(errors::INVALID_PAYMENTS));
    assert_eq!(z.collateral_units(id), 10);
    assert_eq!(z.debt_raw(id), debt);
}
```
