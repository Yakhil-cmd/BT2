### Title
Whole-unit liquidation gap permanently rejects every repayment in a narrow debt band - ([File: contracts/controller/src/positions/liquidation/math.rs])

### Summary
A borrower can create an unhealthy account whose sole collateral is a listed asset with fewer than 3 decimals and whose debt sits in a narrow arithmetic gap. In that state, `liquidate` rejects every possible `debt_payments` amount: the quote is below the debt, but no payment can back even one whole collateral unit. The position therefore remains temporarily unliquidatable while its collateral remains locked by the solvency check.

### Finding Description
`normalize_repayment_plan` calls `whole_unit_repayment` only for a non-insolvent account with exactly one supply position whose `asset_decimals < MIN_BORROWABLE_ASSET_DECIMALS`. That helper can either promote the quote to the full debt or raise it to a repayment that backs one whole collateral unit, but it intentionally leaves the original quote unchanged in a residual band. [1](#0-0) 

Specifically, when:

```text
unit_at_bonus < total_debt + one_unit_per_debt_leg_usd
```

the full-close promotion is skipped. [2](#0-1) 

Then, when:

```text
unit_repayment >= total_debt
```

the one-unit promotion is also skipped. [3](#0-2) 

This leaves the reachable dead zone:

```text
unit_at_bonus - one_unit_per_debt_leg_usd < total_debt <= unit_repayment
```

For a sub-3-decimal collateral leg, a non-full repayment seizure is rounded down to whole token units. If the retained curve quote does not back one whole unit, `seizure_ray` becomes zero and the leg is omitted. [4](#0-3) 

The unbacked repayment is then removed by `release_unbacked_repayment`; when no seizure remains, the second call removes all repayment legs. [5](#0-4)  `liquidate` subsequently rejects the empty repayment with `InvalidPayments`. [6](#0-5) 

A larger offer does not help: because `full_close` is false, it is trimmed back to the unchanged quote before seizure calculation. [7](#0-6)  A smaller offer is not raised either. The project documentation describes the same narrow condition as a state in which “every offer reverts until accrual or a price move ends that state.” [8](#0-7) 

### Impact Explanation
This is a temporary freezing-of-funds and liquidation-liveness failure. While the account is in the band:

- No `controller::liquidate` call can succeed, regardless of the offered amount or `SeizeMode`.
- The borrower cannot withdraw the relevant collateral because doing so would worsen the already below-1 health factor.
- `clean_bad_debt` is unavailable because the account is not insolvent in the required `total_debt > total_collateral` sense.
- Interest continues accruing against lenders while the collateral cannot be seized.

The state ends only when debt accrual, collateral/debt price movement, repayment, or another account change moves the arithmetic outside the band. No privileged action is required to create the state.

### Likelihood Explanation
Likelihood is constrained but reachable by an unprivileged borrower:

1. The market must contain a collateral asset with fewer than 3 decimals.
2. The collateral must be the account’s only supply position.
3. The borrower must size debt inside a very narrow USD-width band approximately equal to `unit_repayment - unit_at_bonus + rounding`.
4. The account must be below `HF = 1` while remaining non-insolvent (`total_collateral >= total_debt`), which is possible because HF uses threshold-weighted collateral.

The borrower controls the collateral amount and can submit a precise `borrow` amount after observing current prices and indexes. The issue does not require oracle manipulation, malformed token behavior, privileged flags, or a failed external service.

### Recommendation
Make the whole-unit promotion exhaustive. In `whole_unit_repayment`, when the account qualifies for whole-unit handling and `unit_repayment >= total_debt`, promote the quote to `total_debt` rather than returning the unchanged quote. Alternatively, add an explicit fallback that selects the smallest repayment capable of seizing one whole unit whenever the unchanged quote would seize zero.

Add a regression test in `tests/test-harness/tests/controller/zero_decimal_collateral.rs` that places `total_debt` strictly between `unit_at_bonus - one_unit_per_debt_leg_usd` and `unit_repayment`, then asserts a `liquidate` call succeeds and seizes one whole unit.

### Proof of Concept
Conceptual transaction sequence for a listed 0-decimal collateral `LOW` and a 6-decimal debt asset `USDC`:

1. Borrower calls:

   ```text
   controller::supply(
       caller = borrower,
       account_id = 0,
       spoke_id = S,
       assets = [((hub_id = H, asset = LOW), amount = 1)]
   )
   ```

   Suppose one `LOW` unit has USD value `U`.

2. Borrower calls:

   ```text
   controller::borrow(
       caller = borrower,
       account_id = returned_id,
       borrows = [((hub_id = H, asset = USDC), amount = D_raw)],
       to = borrower
   )
   ```

   Choose `D_raw` such that:

   ```text
   floor(U / (1 + bonus)) - usd(one USDC base unit)
       < usd(D_raw)
       <= ceil((U + max(U / 1e6, 1)) / (1 + bonus))
   ```

   For example, with `U = $1000` and `bonus = 10%`, the dead interval is approximately:

   ```text
   $909.090908 < D <= $909.091818
   ```

3. Ensure the account is unhealthy through its collateral threshold, for example `C >= D` but `threshold × C < D`. This yields `HF < 1` while the account remains non-insolvent.

4. Any liquidator calls:

   ```text
   controller::liquidate(
       liquidator,
       account_id,
       debt_payments = [((hub_id = H, asset = USDC), offered)],
       seize_mode = SeizeMode::Transfer
   )
   ```

   Every choice of `offered` fails:

   - `offered <= quote`: seizure floors to zero and the repayment is removed.
   - `offered > quote` but not a full close: it is trimmed back to `quote`.
   - `offered >= debt`: still not treated as full close because the unchanged quote remains below debt, so it is also trimmed to `quote`.

   The resulting plan has no seizure and no repayment legs, causing `InvalidPayments` before token settlement.

### Citations

**File:** contracts/controller/src/positions/liquidation/math.rs (L193-205)
```rust
    let full_close = ideal_repayment_usd >= snap.total_debt;

    let mut final_repayment_tokens = repaid_tokens;
    if !full_close && total_debt_payment_usd > ideal_repayment_usd {
        let excess_usd = total_debt_payment_usd.checked_sub(env, ideal_repayment_usd);
        process_excess_payment(
            env,
            &mut final_repayment_tokens,
            &mut refunds,
            excess_usd,
            insolvent,
        );
    }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L235-290)
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

    let one_plus_bonus = Wad::ONE.checked_add(env, bonus.to_wad(env));
    let unit_usd = Wad::from_token(env, 1, feed.asset_decimals).mul(env, feed.price);
    let unit_with_margin =
        unit_usd.checked_add(env, Wad::from((unit_usd.raw() / 1_000_000).max(1)));
    if quote_usd.mul(env, one_plus_bonus) >= unit_with_margin {
        return quote_usd;
    }
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

**File:** contracts/controller/src/positions/liquidation/math.rs (L401-429)
```rust
        if !repayment.seize_all
            && feed.asset_decimals < MIN_BORROWABLE_ASSET_DECIMALS
            && seizure_ray < actual_ray
        {
            if repayment.repays_all_debt {
                let whole = seizure_ray.to_asset_ceil(env, feed.asset_decimals);
                seizure_ray = Ray::from_asset(env, whole, feed.asset_decimals).min(actual_ray);
            } else {
                let whole = seizure_ray.to_asset_floor(env, feed.asset_decimals);
                seizure_ray = Ray::from_asset(env, whole, feed.asset_decimals);
                let whole_usd = seizure_ray.to_wad(env).mul(env, feed.price);
                if seizure_for_asset_usd > whole_usd {
                    unseized_usd = unseized_usd
                        .checked_add(env, seizure_for_asset_usd.checked_sub(env, whole_usd));
                }
            }
        }

        if seizure_ray <= Ray::ZERO {
            continue;
        }

        let capped_ray = if repayment.seize_all {
            actual_ray
        } else {
            seizure_ray.min(actual_ray)
        };
        if capped_ray <= Ray::ZERO {
            continue;
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L73-79)
```rust
    let (seized_collaterals, unbacked_usd) =
        calculate_seized_collateral(env, account, totals.total_collateral, &repayment, cache);
    release_unbacked_repayment(env, &mut repayment, unbacked_usd);
    if unbacked_usd > Wad::ZERO && seized_collaterals.is_empty() {
        let repay_usd = repayment.repay_usd;
        release_unbacked_repayment(env, &mut repayment, repay_usd);
    }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L57-67)
```rust
    // Share payment normalization and positivity checks with the estimate view.
    let liquidation_plan = plan::build_liquidation_plan(env, &account, debt_payments, &mut cache);
    let offered = liquidation_plan
        .repayment
        .full_close
        .then(|| payments::aggregate_positive_payments(env, debt_payments));

    let result = liquidation_plan.into_result();

    require_non_empty_payments(env, &result.repaid);

```

**File:** docs/reference/formulas.md (L302-308)
```markdown
The HF-preserving bonus cap keeps `1 + b <= C / D`, so the sale of one unit does
not lower `C / D`. Thus a solvent account whose only supply leg is below 3
decimals and holds a whole unit stays liquidatable below `HF = 1`, by a
one-unit sale or by a full close. There is one exception. While
`floor(U / (1 + b)) - R < D <= ceil((U + m) / (1 + b))`, neither rule 1 nor
rule 2 applies. If the curve quote then backs less than one unit, every offer
reverts until accrual or a price move ends that state.
```
