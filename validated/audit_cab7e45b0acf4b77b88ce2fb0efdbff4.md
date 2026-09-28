### Title
Torn risk-tuple restamp lets a borrower combine the new listing's higher LTV with the stale higher liquidation threshold, borrowing above any limit the listing ever allowed - (File: contracts/controller/src/risk/params.rs)

### Summary
Each supply position stores its own `(LTV, liquidation_threshold, bonus, fee)` tuple, but the refresh paths update it non-atomically: `restamp_listed_supply_ltv` unconditionally overwrites `loan_to_value` from the live `SpokeAssetConfig`, while `liquidation_threshold`/bonus/fee are only refreshed through `apply_gated_liquidation_params`, which deliberately keeps the old tuple when the new one "favors the liquidator" and the account's HF is below 1.05. Like the Xen half-updated page-table entry, the position is left half-written: one field from the new listing, the rest from the old. The borrow gate then enforces `min(stored LTV, stored LT)`, which can exceed the limit of both the old and the new listing configuration. [1](#0-0) [2](#0-1) 

### Finding Description
- `restamp_listed_supply_ltv` (params.rs:44-64) copies `config.loan_to_value` into every listed supply position with no health gate. It is reached from the borrow/withdraw/strategy gates and from the permissionless `update_account_threshold(caller, has_risks=false, account_ids)` path (`sync_account_thresholds` with `RiskRefreshScope::LtvOnly`, which never loads debt or applies the LT tuple). [3](#0-2) 
- `apply_gated_liquidation_params` (params.rs:68-93) skips the LT/bonus/fee write whenever `favors_liquidator` is true (e.g., the new LT is lower) and the account's HF computed with the new LT is below `THRESHOLD_UPDATE_MIN_HF_RAW` (1.05). The call still succeeds; only the tuple write is skipped. [4](#0-3) 
- `calculate_account_risk_totals` then computes `effective_ltv = position.loan_to_value.min(position.liquidation_threshold)` and weights HF by the stored `liquidation_threshold`. [5](#0-4) 
- `require_post_pool_risk_gates` admits the borrow when `ltv_collateral >= total_debt` and `HF >= 1`, both computed on the torn tuple. [6](#0-5) 

Result: after a governance edit that raises LTV and cuts LT (e.g., old `(LTV 5000, LT 8000)` → new `(LTV 9000, LT 6000)`), an account holding the stale tuple gets `effective_ltv = min(9000, 8000) = 8000` — strictly above the old limit (5000) and the new intended limit (6000). The stickiness is confirmed by `poc_lt_cut_stays_sticky_when_hf_below_min` and the LTV-only restamp by `risk_ltv_low_hf` in the admin flow. [7](#0-6) [8](#0-7) 

### Impact Explanation
Protocol insolvency / theft of user funds. The attacker borrows up to `min(new LTV, stale LT)` — more debt per unit of collateral than any listing state ever authorized — while the stale higher LT also raises the HF numerator, so the position cannot be liquidated until it is deeper underwater than the intended threshold. The attacker withdraws the excess borrowed assets; when the position finally becomes liquidatable at the stale boundary, collateral backing the over-borrowed debt is insufficient, producing bad debt that `apply_bad_debt_to_supply_index` socializes across all suppliers of that market. [9](#0-8) 

### Likelihood Explanation
Requires a listing edit that raises LTV while cutting LT, plus an account whose HF under the new LT sits below 1.05 so the gate holds the old tuple — the attacker can engineer this by borrowing toward the limit first, then calling `borrow`/`withdraw` or the permissionless `update_account_threshold(caller, false, [id])` to force the LTV-only restamp. Every step is reachable by a single unprivileged address; only the parameter change is privileged, and risk-parameter tuning is a routine governance operation.

### Recommendation
Make the tuple update atomic in effect: when `apply_gated_liquidation_params` declines to apply the new LT tuple, also pin `loan_to_value` to `min(new LTV, stored LT)` (or skip the LTV restamp entirely), so `effective_ltv` can never exceed what either the old or the new listing permits. Equivalently, restamp LTV and the LT tuple under the same gate in `restamp_listed_supply_ltv` and `refresh_supply_risk_params`.

### Proof of Concept
1. Spoke listing for collateral asset C: `ltv=5000, lt=8000`. Alice supplies $10,000 of C and borrows ~$4,900 (near the 5000 limit, keeping HF(C@8000) ≈ 1.63 > 1 but HF(C@6000) ≈ 1.22 — below the 1.05 gate only after interest/price drift; alternatively borrow ~$4,700 so HF@6000 < 1.05 immediately: needs debt > 8000·C/1.05... simplest: borrow to LTV limit then let interest accrue until HF(with LT=6000) < 1.05).
2. Governance executes `edit_asset_in_spoke` setting `ltv=9000, lt=6000`.
3. Attacker (any caller) calls `update_account_threshold(caller, has_risks=false, [alice_id])` — or Alice simply calls `borrow`/`withdraw` — triggering `restamp_listed_supply_ltv`: stored LTV becomes 9000, stored LT stays 8000 because `favors_liquidator` is true and `clears_min_hf` fails.
4. Alice calls `borrow`: gate enforces `min(9000,8000)·$10,000 = $8,000` of LTV collateral and `HF = 8000·$10,000/debt ≥ 1`. She borrows up to ~$8,000 — versus the intended $6,000 cap — and withdraws the proceeds.
5. The debt is now backed by collateral at a 80 % margin the protocol never configured; if C's price drops ~25 %, liquidation at the stale LT boundary cannot recover the over-borrowed amount, and the residual is written down via `apply_bad_debt_to_supply_index`, harming all suppliers.

### Citations

**File:** contracts/controller/src/risk/params.rs (L44-64)
```rust
pub(crate) fn restamp_listed_supply_ltv(cache: &mut Context, account: &mut Account) -> bool {
    let mut changed = false;
    let keys = account.supply_positions.keys();
    for hub_asset in keys.iter() {
        let Some(listed) = cache.cached_spoke_asset(account.spoke_id, &hub_asset) else {
            continue;
        };
        let config: AssetConfig = (&listed).into();
        let Some(raw) = account.supply_positions.get(hub_asset.clone()) else {
            continue;
        };
        let mut position = AccountPosition::from(&raw);
        if position.loan_to_value.raw() == config.loan_to_value.raw() {
            continue;
        }
        position.loan_to_value = config.loan_to_value;
        update_or_remove_supply_position(account, &hub_asset, &position);
        changed = true;
    }
    changed
}
```

**File:** contracts/controller/src/risk/params.rs (L76-99)
```rust
    if favors_liquidator(position, effective_config)
        && !account.debt_free()
        && !clears_min_hf(
            env,
            cache,
            account,
            hub_asset,
            position,
            effective_config.liquidation_threshold,
        )
    {
        return;
    }

    position.liquidation_threshold = effective_config.liquidation_threshold;
    position.liquidation_bonus = effective_config.liquidation_bonus;
    position.liquidation_fees = effective_config.liquidation_fees;
}

/// Detects a lower threshold or fee, or a higher bonus, than the stored tuple.
fn favors_liquidator(position: &AccountPosition, effective_config: &AssetConfig) -> bool {
    effective_config.liquidation_threshold.raw() < position.liquidation_threshold.raw()
        || effective_config.liquidation_bonus.raw() > position.liquidation_bonus.raw()
        || effective_config.liquidation_fees.raw() < position.liquidation_fees.raw()
```

**File:** contracts/controller/src/risk/params.rs (L121-144)
```rust
/// Allows any authenticated caller to refresh listed supply LTV snapshots.
/// `has_risks` also refreshes gated liquidation tuples and enforces health
/// factor >= 1.05. Rejects execution during a flash loan.
pub(crate) fn update_account_threshold(
    env: &Env,
    caller: Address,
    has_risks: bool,
    account_ids: Vec<u64>,
) {
    validation::require_authorized_caller(env, &caller);

    let scope = if has_risks {
        RiskRefreshScope::FullTuple
    } else {
        RiskRefreshScope::LtvOnly
    };

    let mut cache = Context::new(env);

    for account_id in account_ids {
        cache.reset_spoke_context();
        sync_account_thresholds(env, account_id, scope, &mut cache);
    }
}
```

**File:** contracts/controller/src/risk/totals.rs (L188-198)
```rust
        total_collateral = total_collateral.checked_add(env, value);
        // A gated threshold can stay below refreshed LTV; clamp the borrow limit to it.
        let effective_ltv = position.loan_to_value.min(position.liquidation_threshold);
        ltv_collateral =
            ltv_collateral.checked_add(env, effective_ltv.apply_to_wad_floor(env, gate_value));
        weighted_collateral = weighted_collateral.checked_add(
            env,
            position
                .liquidation_threshold
                .apply_to_wad_floor(env, gate_value),
        );
```

**File:** contracts/controller/src/risk/validation.rs (L41-53)
```rust
    assert_with_error!(
        env,
        totals.ltv_collateral >= totals.total_debt,
        CollateralError::InsufficientCollateral
    );

    spec_hooks::solvency_gate_checked(account);

    assert_with_error!(
        env,
        totals.health_factor >= Wad::ONE,
        CollateralError::InsufficientCollateral
    );
```

**File:** tests/test-harness/tests/controller/security_audit.rs (L489-504)
```rust
    t.try_supply_to_account(BOB, ALICE, "USDC", 1.0)
        .expect("top-up must remain allowed");
    let (ltv_after, lt_after) = supply_ltv_and_lt(&t, id, "USDC");
    assert_eq!(
        ltv_after, 5_000,
        "H-RISK-03/04: LTV always restamps on supply refresh"
    );
    assert_eq!(
        lt_after, 8_000,
        "H-RISK-04: LT stamp must stay sticky when post-cut HF < 1.05"
    );

    assert!(
        !t.can_be_liquidated(ALICE),
        "sticky LT keeps HF ≥ 1 at original prices after listing cut"
    );
```

**File:** tests/integration/flows/admin.sh (L102-105)
```shellscript
    inv risk_ltv_low_hf "$BOB" "$CONTROLLER" -- update_account_threshold --caller "$BOB_ADDR" \
        --has_risks false --account_ids "[$free,$low]" >/dev/null || return 1
    risk_assert_stamps risk_ltv_low_hf_free "$free" "$SAC_RISK" '[5200,6900,800,60]' "$free_before" || return 1
    risk_assert_stamps risk_ltv_low_hf_debt "$low" "$SAC_RISK" '[5200,8100,400,100]' "$low_before"
```

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```
