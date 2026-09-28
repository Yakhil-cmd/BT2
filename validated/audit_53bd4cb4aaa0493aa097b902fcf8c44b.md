### Title
Unprivileged cross-account LTV restamping in `update_account_threshold` freezes a victim's withdrawals - (File: contracts/controller/src/risk/params.rs)

### Summary
`update_account_threshold` is callable by any authenticated address on arbitrary `account_ids` with no owner/delegate check — an IDOR-style cross-account write analogous to the Gitea report. With `has_risks = false` it unconditionally rewrites each victim supply position's stored `loan_to_value` to the currently listed value, skipping the health-factor gate. Because `calculate_ltv_collateral_wad` uses the stored `min(LTV, liquidation_threshold)` and `require_post_pool_risk_gates` demands `ltv_collateral >= total_debt` on every `withdraw`, an attacker can restamp a foreign account after governance lowers an asset's LTV and push its LTV-weighted collateral below its debt, reverting all withdrawals.

### Finding Description
`update_account_threshold(env, caller, has_risks, account_ids)` only calls `require_authorized_caller` (i.e., `caller.require_auth()`) and then iterates any caller-supplied `account_ids` — no `require_owner_or_delegate` is ever applied to the target accounts. In `LtvOnly` scope (`has_risks = false`), `refresh_supply_risk_params` sets `position.loan_to_value = effective_config.loan_to_value` with no solvency precondition; the `clears_min_hf` gate inside `apply_gated_liquidation_params` only runs for `FullTuple`. The written `loan_to_value` feeds `effective_ltv = position.loan_to_value.min(position.liquidation_threshold)` in `calculate_ltv_collateral_wad`, and `require_post_pool_risk_gates` reverts `withdraw` (and `borrow`) whenever `totals.ltv_collateral < totals.total_debt`. Accounts that borrowed under a previously higher LTV are exactly the ones this transition pushes under water on the LTV axis even while their health factor stays ≥ 1 (HF uses `liquidation_threshold`, which `LtvOnly` never touches).

### Impact Explanation
Temporary freezing of funds: after governance tightens a spoke asset's `loan_to_value`, any unprivileged address calls `update_account_threshold(attacker, false, [victim_id])`, rewriting the victim's LTV snapshot. Every subsequent `withdraw` and `borrow` by the victim reverts with `InsufficientCollateral` until the victim repays enough debt to restore `ltv_collateral >= total_debt` — a forced deleveraging imposed by a stranger on an account that is healthy by the liquidation metric and would not be liquidatable.

### Likelihood Explanation
The trigger requires a governance LTV reduction on an asset already used as borrowed collateral — a normal, documented tightening operation (`edit_asset_in_spoke` may only tighten flags/params). From that moment the attack is one permissionless transaction per victim, with no cost beyond the call itself, and it cannot be blocked by the victim since the restamp is applied unconditionally to listed assets.

### Recommendation
In `sync_account_thresholds`, either (a) require owner-or-delegate authorization when the refresh would *lower* `loan_to_value` on an account with outstanding debt, or (b) skip writes that reduce `ltv_collateral` below `total_debt`, mirroring the `clears_min_hf` gate already used for the liquidation tuple — i.e., only apply a lowered LTV when the account stays solvent (or is debt-free) under the new snapshot.

### Proof of Concept
1. Governance lowers `loan_to_value` for USDC in spoke `s` from 0.80 to 0.50.
2. Victim's account supplies $100k USDC (stale LTV 0.80) with $60k debt: `ltv_collateral` under old snapshot = $80k ≥ $60k; HF ≈ 1.3 via untouched `liquidation_threshold`.
3. Attacker (any address) calls `controller.update_account_threshold(attacker, false, [victim_id])`. `sync_account_thresholds` → `refresh_supply_risk_params` writes `loan_to_value = 0.50` to the victim's stored position (`params.rs:35`, `params.rs:59-60`), with `FullTuple` gating skipped.
4. Victim calls `withdraw(caller=victim, account_id, [(USDC, 1)])`. `require_post_pool_risk_gates` computes `effective_ltv = min(0.50, LT)` → `ltv_collateral ≈ $50k < $60k` → reverts `InsufficientCollateral` (`validation.rs:41-45`, `totals.rs:95` and `totals.rs:190`). All withdrawals and borrows are blocked until the victim repays ~$10k+ of debt. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/controller/src/risk/params.rs (L56-60)
```rust
        if position.loan_to_value.raw() == config.loan_to_value.raw() {
            continue;
        }
        position.loan_to_value = config.loan_to_value;
        update_or_remove_supply_position(account, &hub_asset, &position);
```

**File:** contracts/controller/src/risk/params.rs (L76-88)
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
```

**File:** contracts/controller/src/risk/params.rs (L124-144)
```rust
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

**File:** contracts/controller/src/risk/validation.rs (L41-45)
```rust
    assert_with_error!(
        env,
        totals.ltv_collateral >= totals.total_debt,
        CollateralError::InsufficientCollateral
    );
```

**File:** contracts/controller/src/risk/totals.rs (L189-192)
```rust
        // A gated threshold can stay below refreshed LTV; clamp the borrow limit to it.
        let effective_ltv = position.loan_to_value.min(position.liquidation_threshold);
        ltv_collateral =
            ltv_collateral.checked_add(env, effective_ltv.apply_to_wad_floor(env, gate_value));
```
