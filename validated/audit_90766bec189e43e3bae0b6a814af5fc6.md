### Title
Partial liquidation can consume repayment while seizing no collateral - ([File: contracts/controller/src/positions/liquidation/mod.rs](contracts/controller/src/positions/liquidation/mod.rs))

### Summary
`Controller::liquidate` accepts a positive partial repayment even when every calculated collateral seizure rounds to zero tokens or zero shares. The controller first pulls the liquidator's debt tokens and credits the repayment, then iterates over an empty seizure vector, so the liquidator permanently loses the repayment without receiving collateral or a refund. This is analogous to the reported partial-settlement flaw: the protocol accepts and settles a partial action while providing no benefit to the caller.

### Finding Description
`build_liquidation_plan` derives `seized_collaterals` from `calculate_seized_collateral`, but it does not reject an empty seizure vector. It releases unbacked repayment only when `unbacked_usd > Wad::ZERO`; however, ordinary seizure legs that floor to zero shares or zero token units are skipped without adding their USD value to `unseized_usd`. [1](#0-0) 

Inside `calculate_seized_collateral`, a leg with `seized_scaled <= Ray::ZERO` or `capped_amount <= 0` is silently omitted from the `seized` vector. [2](#0-1)  The returned `unseized_usd` only accounts for low-decimal whole-unit rounding; it does not include all legs dropped by the later share/token rounding checks. [3](#0-2) 

`process_liquidation` only validates that `result.repaid` is nonempty. It does not require `result.seized` to be nonempty before executing repayment. [4](#0-3)  `apply_liquidation_repayments` then transfers each planned debt amount from the liquidator to the pool and submits those received amounts to `apply_repay_batch`. [5](#0-4)  After repayment completes, the seizure application iterates `seized`; when that vector is empty, both Transfer and Credit modes perform no collateral payout or share credit. [6](#0-5) 

The repository's own liquidation guidance identifies this behavior: an estimate with empty `seized_collaterals` is executable, and "the liquidator would pay and receive no collateral." [7](#0-6) 

### Impact Explanation
An unprivileged liquidator can invoke `liquidate(caller, account_id, debt_payments, SeizeMode::Transfer)` or a valid `SeizeMode::Credit` receiver on an unhealthy account and transfer real debt tokens to the pool while receiving zero collateral. The borrower benefits from reduced debt, while the liquidator receives neither collateral tokens nor credited supply shares. This is a direct loss of user funds and matches the accepted impact category of theft/loss of user funds.

The loss is bounded by the accepted repayment legs, but it can occur for any positive repayment when all pro-rata collateral legs are dropped by rounding. The protocol documentation explicitly notes that a tiny repayment can retire debt while its pro-rata seizure rounds to zero. [8](#0-7) 

### Likelihood Explanation
Likelihood is moderate. It does not require privileged access, oracle manipulation, a malicious token, or a special callback. It requires an unhealthy account whose collateral/price/share/index combination causes every partial seizure leg to round to zero payable collateral. Such configurations are reachable through ordinary market listings with different token decimals, prices, indexes, and position sizes. The protocol guidance tells operators to reject empty `seized_collaterals`, but the contract itself does not enforce that requirement. [7](#0-6) 

### Recommendation
Reject liquidation plans whose measured or planned repayment is positive but produce no executable collateral seizure. In `build_liquidation_plan`, after `calculate_seized_collateral` and `release_unbacked_repayment`, revert with `InvalidPayments` if `repayment.repaid` is nonempty while `seized_collaterals` is empty. More generally, track all collateral USD omitted because `seized_scaled` or `capped_amount` rounds to zero and release the corresponding repayment, so either every paid unit purchases collateral or the call atomically reverts before pulling funds.

### Proof of Concept
Conceptual execution path:

1. Create or observe an unhealthy account with positive collateral and debt.
2. Submit a small positive debt repayment through `Controller::liquidate`.
3. `calculate_repayment_amounts` produces a positive `RepayEntry`.
4. `calculate_seized_collateral` computes a pro-rata collateral amount that rounds to zero shares or zero token units for every collateral leg, so it returns an empty `seized` vector.
5. `build_liquidation_plan` does not revert because `unbacked_usd == 0` for these dropped legs.
6. `process_liquidation` sees nonempty `result.repaid` and calls `apply_liquidation_repayments`.
7. The debt token is transferred from the liquidator to the pool and `pool.repay` burns the borrower's debt shares.
8. `apply_liquidation_seizures` or `apply_liquidation_share_credit` receives an empty vector and transfers/credits nothing.
9. The transaction commits: the borrower's debt decreases, the liquidator's debt-token balance decreases, and the liquidator receives no collateral.

### Citations

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

**File:** contracts/controller/src/positions/liquidation/math.rs (L401-416)
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
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L456-467)
```rust
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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L64-69)
```rust
    let result = liquidation_plan.into_result();

    require_non_empty_payments(env, &result.repaid);

    let received_usd = apply::apply_liquidation_repayments(
        env,
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L77-93)
```rust
    // Under-delivering debt tokens must reduce the collateral awarded.
    let repay_usd = math::sum_repaid_usd(env, &result.repaid);
    let seized = math::scale_seizures_to_received(env, &result.seized, received_usd, repay_usd);
    match &mut receiver {
        None => {
            apply::apply_liquidation_seizures(env, liquidator, &mut account, &seized, &mut cache)
        }
        Some((_, receiving_account)) => {
            apply::require_credit_position_limit(env, receiving_account, &seized, &mut cache);
            apply::apply_liquidation_share_credit(
                env,
                &mut account,
                receiving_account,
                &seized,
                &mut cache,
            );
        }
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L54-65)
```rust
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
```

**File:** skills/xoxno-lending-liquidations/SKILL.md (L178-180)
```markdown
Reject an estimate whose `seized_collaterals` is empty. The contract accepts a
liquidation that repays debt and seizes nothing, so the liquidator would pay
and receive no collateral.
```

**File:** docs/explanation/threat-model.md (L277-282)
```markdown
Liquidators bear execution-time bonus, rounding, and route-quality risk.
A tiny repayment can retire debt while its pro-rata seizure rounds to zero.
Admission does not couple collateral price, decimals, bonus and fee to the
minimum-collateral floor. Expensive low-decimal collateral can yield zero
seizure even for a $5 repayment; assess that precision risk before listing.
The [seizure fixture tests](../../contracts/controller/tests/positions/liquidation_math.rs) reproduce this limit.
```
