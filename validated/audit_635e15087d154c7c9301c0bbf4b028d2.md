### Title
`liquidate` accepts a positive debt repayment while rounding every collateral-seizure leg to zero - ([File: contracts/controller/src/positions/liquidation/math.rs](contracts/controller/src/positions/liquidation/math.rs))

### Summary
A permissionless liquidator can successfully call `liquidate`, transfer debt tokens to the pool, and reduce the borrower’s debt while receiving no collateral because the liquidation plan does not require the resulting `seized` vector to be nonempty. [1](#0-0) 

### Finding Description
The liquidation planner drops a collateral leg whenever `seizure_ray`, `capped_ray`, `seized_scaled`, or `capped_amount` rounds to zero. [2](#0-1) [3](#0-2) 

For collateral with at least `MIN_BORROWABLE_ASSET_DECIMALS`, the fractional collateral value discarded by these zero-rounding checks is not accumulated into `unseized_usd`; only the special low-decimal branch contributes to that refund amount. [4](#0-3) 

Consequently, `release_unbacked_repayment` is not invoked when every seizure leg is dropped through the ordinary zero-share or zero-token paths, leaving a positive `repaid` vector and an empty `seized` vector. [5](#0-4) 

`LiquidationPlan::validate` checks only the entries that remain in `seized`; it never rejects an empty seizure list. [6](#0-5) 

Execution then explicitly requires only `result.repaid` to be nonempty, transfers the liquidator’s planned debt tokens to the pool, burns borrower debt, and iterates over an empty seizure list. [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
The liquidator permanently loses the accepted repayment amount while receiving neither underlying collateral nor credited supply shares. [10](#0-9) 

This is direct loss of user funds rather than a harmless failed transaction: the pool receives measurable debt tokens and the borrower’s liability is reduced, but the collateral payout side is a no-op. [11](#0-10) 

The issue is most reachable for a small partial liquidation against a collateral whose smallest transferable unit is valuable enough that the allocated seizure is less than one unit. [12](#0-11) 

### Likelihood Explanation
Any liquidator can reach the path through the public `liquidate` entrypoint with a positive `debt_payments` vector and `SeizeMode::Transfer`; no privileged role or leaked authorization is required. [13](#0-12) 

The borrower only needs an underwater account and collateral priced such that a permitted partial repayment maps to less than one collateral unit or less than one scaled share. [14](#0-13) 

Although a caller can reject an empty estimate client-side, the state-changing entrypoint itself does not enforce that invariant, so simulation mistakes, stale estimates, and generic liquidation bots can still submit the losing transaction. [15](#0-14) 

### Recommendation
Before moving repayment, require `!result.repaid.is_empty() && !result.seized.is_empty()` in `process_liquidation`, or equivalently make `LiquidationPlan::validate` reject a positive repayment with no executable seizure legs. [16](#0-15) 

The repayment planner should also account for collateral value dropped by `seized_scaled == 0` and `capped_amount == 0`, not just the existing low-decimal `unseized_usd` path, so unbacked repayment is refunded before execution. [4](#0-3) [3](#0-2) 

### Proof of Concept
1. Create a liquidatable borrower whose only collateral is a listed asset with `asset_decimals >= MIN_BORROWABLE_ASSET_DECIMALS` and a sufficiently high whole-unit price that a small accepted debt repayment backs less than one collateral base unit.
2. Call `Controller::liquidate(liquidator, account_id, debt_payments, SeizeMode::Transfer)` with a positive payment below the maximum repayment quote.
3. `calculate_seized_collateral` computes a positive pro-rata USD allocation, but its share/token conversion rounds below one unit, so the leg reaches `continue` and `seized` remains empty.
4. `process_liquidation` accepts the plan because `result.repaid` is nonempty and transfers the liquidator’s tokens to the pool.
5. `apply_liquidation_seizures` iterates over the empty vector, so the borrower’s debt is reduced while the liquidator receives no collateral.

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L64-82)
```rust
    let result = liquidation_plan.into_result();

    require_non_empty_payments(env, &result.repaid);

    let received_usd = apply::apply_liquidation_repayments(
        env,
        liquidator,
        &mut account,
        &result.repaid,
        offered.as_ref(),
        &mut cache,
    );

    // Under-delivering debt tokens must reduce the collateral awarded.
    let repay_usd = math::sum_repaid_usd(env, &result.repaid);
    let seized = math::scale_seizures_to_received(env, &result.seized, received_usd, repay_usd);
    match &mut receiver {
        None => {
            apply::apply_liquidation_seizures(env, liquidator, &mut account, &seized, &mut cache)
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L54-69)
```rust
    pub(crate) fn validate(&self, env: &Env) {
        self.repayment.validate(env);

        for entry in self.seized.iter() {
            if entry.amount <= 0 || entry.protocol_fee < 0 || entry.protocol_fee > entry.amount {
                panic_with_error!(env, GenericError::InternalError);
            }
            if entry.scaled_amount <= 0
                || entry.bonus_scaled < 0
                || entry.bonus_scaled > entry.scaled_amount
                || i128::from(entry.liquidation_fees) >= BPS
            {
                panic_with_error!(env, GenericError::InternalError);
            }
        }
    }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L383-416)
```rust
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let actual_ray = position.scaled_amount.mul(env, market_index.supply_index);
        let asset_value = risk::position_value(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );

        let share = asset_value.div(env, total_collateral);
        let seizure_for_asset_usd = total_seizure_usd.mul(env, share);

        let seizure_amount_wad = seizure_for_asset_usd.div(env, feed.price);
        let mut seizure_ray = seizure_amount_wad.to_ray(env);

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
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L419-429)
```rust
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

**File:** contracts/controller/src/positions/liquidation/math.rs (L447-467)
```rust
        let seized_scaled = if is_full_close {
            position.scaled_amount
        } else {
            capped_ray.div_floor(env, market_index.supply_index)
        };
        // Independent conversions must still preserve `bonus <= seized`.
        let bonus_scaled = bonus_ray
            .div_floor(env, market_index.supply_index)
            .min(seized_scaled);
        if seized_scaled <= Ray::ZERO {
            continue;
        }

        let capped_amount = if is_full_close {
            capped_ray.to_asset(env, feed.asset_decimals)
        } else {
            capped_ray.to_asset_floor(env, feed.asset_decimals)
        };
        if capped_amount <= 0 {
            continue;
        }
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

**File:** contracts/controller/src/positions/liquidation/plan.rs (L91-96)
```rust
    let plan = LiquidationPlan {
        repayment,
        seized: seized_collaterals,
    };
    plan.validate(env);
    plan
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L45-79)
```rust
    for entry in repaid.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &entry.hub_asset,
            FreezePolicy::AllowOnExit,
        );

        let pull = offered.map_or(entry.amount, |offers| {
            offered_amount(env, offers, &entry.hub_asset)
        });
        // Credit only tokens received by the pool.
        let received = payments::transfer_amount_measured(
            env,
            &entry.hub_asset.asset,
            liquidator,
            &pool_addr,
            pull,
            GenericError::AmountMustBePositive,
        );

        // Planned amounts are positive, so the division is safe.
        let leg_usd = if received >= entry.amount {
            Wad::from(entry.usd_wad)
        } else {
            Wad::from(mul_div_floor(env, entry.usd_wad, received, entry.amount))
        };
        received_usd = received_usd.checked_add(env, leg_usd);

        let position: DebtPosition =
            (&expect_invariant(env, account.borrow_positions.get(entry.hub_asset.clone()))).into();
        actions.push_back(make_pool_action(&position, received, entry.hub_asset));
    }
    apply_repay_batch(
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L97-129)
```rust
pub(crate) fn apply_liquidation_seizures(
    env: &Env,
    liquidator: &Address,
    account: &mut Account,
    seized: &Vec<SeizeEntry>,
    cache: &mut Context,
) {
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
    for entry in seized.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &entry.hub_asset,
            FreezePolicy::SeizureLeg,
        );

        let position: AccountPosition =
            (&expect_invariant(env, account.supply_positions.get(entry.hub_asset.clone()))).into();
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, entry.amount, entry.hub_asset),
            protocol_fee: entry.protocol_fee,
        });
    }
    apply_withdraw_batch(
        env,
        account,
        liquidator,
        WithdrawKind::Liquidation,
        events::PositionAction::LiqSeize,
        &entries,
        cache,
    );
```

**File:** contracts/controller/src/lib.rs (L144-158)
```rust
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }
```
