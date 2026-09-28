### Title
Tightened liquidation risk parameters are silently discarded for exactly the distressed accounts they target — `apply_gated_liquidation_params` early-returns while `update_account_threshold` then reverts on the HF gate (File: contracts/controller/src/risk/params.rs)

### Summary
The Dex report's bug class is "a security-relevant configuration is constructed and then silently discarded because a later mechanism supersedes it." XOXNO Lending has the same shape: spoke-listing risk parameters (`liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`) are configured per market, but restamping them onto live positions is gated by the account's health. `update_account_threshold(caller, has_risks=true, ...)` is permissionless, yet for any account whose health factor is already below `THRESHOLD_UPDATE_MIN_HF_RAW` (1.05) the new liquidation tuple is silently skipped per position, and the final whole-account HF assertion reverts the entire call — so tightened parameters can never be applied to the accounts that most need them.

### Finding Description
`refresh_supply_risk_params` unconditionally restamps `loan_to_value`, but delegates the liquidation tuple to `apply_gated_liquidation_params`, which returns early (discarding the new `liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`) whenever the change `favors_liquidator` and the account has debt and fails `clears_min_hf` [1](#0-0) . `favors_liquidator` is precisely a risk tightening: lower threshold, higher bonus, or lower fees [2](#0-1) .

Worse, `sync_account_thresholds` under `FullTuple` scope then asserts the post-update health factor is ≥ 1.05 and reverts the whole batch otherwise [3](#0-2) . So there are two discard layers:

- `has_risks=false` (LtvOnly): only LTV is restamped; the liquidation tuple is never touched [4](#0-3) .
- `has_risks=true` (FullTuple): per-position silent skip for sub-1.05 accounts, and even when the skip path is taken the trailing HF assert can still revert the call, so nothing persists.

The account's stored `liquidation_threshold` — the value that actually feeds `calculate_account_risk_totals` and liquidation eligibility — remains the old, more generous value indefinitely. Like the Dex `tlsConfig` that was built with TLS 1.2 minimum but thrown away by the cert reloader, the configured tightening exists in storage but never reaches the positions where it matters.

### Impact Explanation
When governance tightens a listing (lower `liquidation_threshold`, higher `liquidation_bonus`) in response to deteriorating collateral, every account that is already unhealthy — HF below 1.05, the exact population the tightening targets — permanently keeps its old, higher threshold. Those accounts retain inflated threshold-weighted collateral, staying nominally healthier (or appearing further from liquidation) than the current risk configuration intends. An unprivileged borrower with HF in (1.0, 1.05) under the new config can call `update_account_threshold` and observe it revert or silently no-op, then continue borrowing against the stale LTV restamp while their liquidation tuple stays stale, increasing the protocol's exposure to bad debt. This is a protocol-insolvency-adjacent failure: configured risk reduction is unreachable for distressed books.

### Likelihood Explanation
Requires a governance risk tightening (privileged trigger, which lowers the rating), but the discard path is deterministic and reachable by any unprivileged `update_account_threshold` caller, and it triggers exactly when accounts are stressed — the common case for a tightening. The failure is silent at the per-position layer (early `return`, no error, `changed` still reflects only the LTV write), so operators reading `get_account_positions` see updated LTVs and may not notice liquidation tuples were never applied.

### Recommendation
Never silently skip the tuple: if `favors_liquidator && !clears_min_hf`, either apply the configured tuple anyway (a liquidation tightening does not need the borrower's consent) or clamp the position's `liquidation_threshold` down to `min(stored, configured)` independently of the bonus/fee direction test, and emit an explicit event when the gate suppresses an update. Also move the final 1.05 assert so it only blocks *increases* in borrower-favorable terms, not tightenings.

### Proof of Concept
1. Account A in spoke S supplies X, borrows Y; stored `liquidation_threshold` = 8000. Price drift puts HF ≈ 1.03.
2. Governance executes `edit_asset_in_spoke` lowering `threshold` to 7500 and raising `bonus` (a `favors_liquidator` change).
3. Anyone calls `update_account_threshold(caller, true, [A])`. In `apply_gated_liquidation_params`, `favors_liquidator` is true, `debt_free` is false, `clears_min_hf` fails → early return; `liquidation_threshold` stays 8000. The trailing `FullTuple` assert on HF ≥ 1.05 reverts the transaction, so even the LTV restamp rolls back.
4. `update_account_threshold(caller, false, [A])` succeeds but writes only `loan_to_value`; the tuple remains stale forever while HF < 1.05.
5. Result: A keeps collateral-weighted HF computed at threshold 8000 — liquidation under the new regime's intent is delayed — and no path exists to restamp the tuple until A's HF recovers above 1.05 on its own.

### Citations

**File:** contracts/controller/src/risk/params.rs (L76-93)
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
```

**File:** contracts/controller/src/risk/params.rs (L96-100)
```rust
fn favors_liquidator(position: &AccountPosition, effective_config: &AssetConfig) -> bool {
    effective_config.liquidation_threshold.raw() < position.liquidation_threshold.raw()
        || effective_config.liquidation_bonus.raw() > position.liquidation_bonus.raw()
        || effective_config.liquidation_fees.raw() < position.liquidation_fees.raw()
}
```

**File:** contracts/controller/src/risk/params.rs (L132-136)
```rust
    let scope = if has_risks {
        RiskRefreshScope::FullTuple
    } else {
        RiskRefreshScope::LtvOnly
    };
```

**File:** contracts/controller/src/risk/params.rs (L221-234)
```rust
    if full_tuple {
        let hf = calculate_account_risk_totals(
            env,
            cache,
            &account.supply_positions,
            &account.borrow_positions,
        )
        .health_factor;
        assert_with_error!(
            env,
            hf >= Wad::from(THRESHOLD_UPDATE_MIN_HF_RAW),
            CollateralError::HealthFactorTooLow
        );
    }
```
