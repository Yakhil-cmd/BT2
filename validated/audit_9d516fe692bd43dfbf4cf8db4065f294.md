### Title
`is_liquidatable`/`liquidate` value collateral with the stale stored `liquidation_threshold`, never clamped to the current config, so accounts that should be liquidatable are not - ([contracts/controller/src/risk/totals.rs](contracts/controller/src/risk/totals.rs))

### Summary
The health factor used by `is_liquidatable`, `liquidate` (via `build_liquidation_plan`'s `HealthFactorTooHigh` gate), and `get_health_factor` is computed from each supply position's **stored** `liquidation_threshold`, while the authoritative value lives in the current `SpokeAssetConfig`/`AssetConfig`. When the stored threshold exceeds the current config threshold — which happens whenever the config is tightened — `weighted_collateral` is overstated, the health factor is overstated, and the account is not flagged liquidatable even though under the actual binding threshold it is below 1.0. The restamp path that could fix it (`apply_gated_liquidation_params`) explicitly skips exactly those weak accounts, so the stale, more permissive bound is permanently used in the liquidation check — a direct analog of using `vp.maxTimesLeverage` where the smaller `maxLevTimes` actually binds.

### Finding Description
`calculate_account_risk_totals_body` computes `weighted_collateral` using `position.liquidation_threshold` read from the stored `AccountPositionRaw`, with no `min(...)` against the current config:

```rust
weighted_collateral = weighted_collateral.checked_add(
    env,
    position
        .liquidation_threshold
        .apply_to_wad_floor(env, gate_value),
);
``` [1](#0-0) 

Note the asymmetry: the borrow limit already clamps to `position.loan_to_value.min(position.liquidation_threshold)` (line 190), but the liquidation-side weight does not clamp to the live config threshold at all.

`is_liquidatable` and the liquidation revert gate both consume this overstated health factor:
- `views::can_be_liquidated` returns `health_factor(env, account_id) < WAD` [2](#0-1) 
- `liquidate` → `build_liquidation_plan` reverts `HealthFactorTooHigh` on the same `HF < WAD` predicate [3](#0-2) 

The stored threshold is only restamped by `refresh_supply_risk_params`/`apply_gated_liquidation_params`, which **returns early** when the new tuple "favors the liquidator" (lower threshold, higher bonus, or lower fees) and the account does not clear HF ≥ 1.05 with the new threshold:

```rust
if favors_liquidator(position, effective_config)
    && !account.debt_free()
    && !clears_min_hf(env, cache, account, hub_asset, position, effective_config.liquidation_threshold)
{
    return;
}
``` [4](#0-3) 

So precisely the accounts that should become liquidatable under the tightened config are the ones whose stale high threshold is retained — and `update_account_threshold(caller, has_risks=true, ...)` (permissionless) cannot force the update, since it runs through the same `sync_account_thresholds` gate [5](#0-4) .

Attack path (permissionless entrypoints):
1. Attacker (or any user) supplies collateral via `supply` and borrows via `borrow`, stamping `liquidation_threshold = config` at origination.
2. The market's `liquidation_threshold` is lowered (an ordinary parameter change, analogous to the report's `maxLevTimes < maxTimesLeverage` precondition).
3. The account's price drifts so that `HF_stored ≥ 1` but `HF_current_config < 1` (and restamping would not clear 1.05, so every `update_account_threshold` call skips it — verified by `clears_min_hf`).
4. Any liquidator calling `liquidate(liquidator, account_id, debt_payments, seize_mode)` hits `HealthFactorTooHigh`; the position accrues debt interest until it becomes genuinely insolvent.

### Impact Explanation
Positions that should be liquidated under the actual current liquidation threshold cannot be liquidated at all — no keeper action can force the restamp or the liquidation. Collateral can deteriorate well below the point where liquidation should have occurred, producing protocol losses and elevated bad-debt creation risk (eventually pushed onto suppliers via the supply-index write-down / `recapitalize` path). Same impact class as the source report.

### Likelihood Explanation
Requires a config tightening of `liquidation_threshold` on a listed collateral asset while open accounts carry debt — a normal operational parameter change, not a bad-parameter edge case. Once crossed, the state is self-sustaining: the gate in `apply_gated_liquidation_params` guarantees the stale threshold persists indefinitely, and every liquidation attempt reverts. Medium likelihood, High impact.

### Recommendation
Mirror the report's mitigation — use the smaller (actual) bound in the check: compute `weighted_collateral` in `calculate_account_risk_totals_body` with `min(position.liquidation_threshold, current_config.liquidation_threshold)` (looking up the live `AssetConfig` for listed assets), so the liquidation check always uses the tightest effective threshold, or at minimum allow `update_account_threshold` to restamp threshold downward for accounts whose hypothetical HF would fall below 1.05 but remain ≥ 1.0, so the liquidation path itself stays reachable.

### Proof of Concept
```text
Setup (harness): standard_two_asset; config USDC ltv 8000 / lt 8000.
1. ALICE supplies 10_000 USDC, borrows 6.0 ETH @ $1_000
   -> weighted = 8000 * 10000e18 = 8000e18-terms; HF ≈ 1.33.
2. Governance lowers USDC liquidation_threshold to 6000.
   Under current config: weighted = 0.6 * 10000 = 6000 USD; debt 6000 USD
   -> HF_true = 1.0 boundary; at $1_010/ETH debt = 6060 -> HF_true ≈ 0.99 < 1.
3. Attempt: ctrl.update_account_threshold(caller, has_risks=true, [alice_id])
   -> apply_gated_liquidation_params: favors_liquidator (8000->6000) and
      clears_min_hf fails (hypothetical HF < 1.05) -> early return; stored lt stays 8000.
   sync_account_thresholds writes nothing for that leg.
4. LIQUIDATOR calls liquidate(... , [(ETH, 0.5)], SeizeMode::Transfer)
   -> build_liquidation_plan sees HF_stored ≈ 1.31 >= 1 -> reverts HealthFactorTooHigh.
5. is_liquidatable(alice_id) == false while the account is under-collateralized
   by the actually binding 6000 threshold — identical to the report's
   underestimated base leading to a missed liquidation.
```
Code anchors: `contracts/controller/src/risk/totals.rs:195-198` (unclamped stored threshold in `weighted_collateral`), `contracts/controller/src/risk/params.rs:76-93` (skip of liquidator-favoring restamps below HF 1.05), `contracts/controller/src/views.rs:47-49` (`can_be_liquidated`), `contracts/controller/src/risk/params.rs:124-144` (permissionless `update_account_threshold` shares the same gate).

Caveat: whether the "stored threshold grandfathering" is an intentional design decision (documented in `skills/xoxno-lending/math.md` and `docs/reference/formulas.md`) affects severity classification; the mechanics above are nevertheless real, reachable by unprivileged `liquidate`/`update_account_threshold` callers, and match the source bug class exactly — the liquidation check uses a looser bound than the currently binding one, permanently blocking liquidations.

### Citations

**File:** contracts/controller/src/risk/totals.rs (L193-198)
```rust
        weighted_collateral = weighted_collateral.checked_add(
            env,
            position
                .liquidation_threshold
                .apply_to_wad_floor(env, gate_value),
        );
```

**File:** contracts/controller/src/views.rs (L45-49)
```rust
/// Returns whether the account's health factor is below 1.0 (WAD), making it
/// eligible for liquidation.
pub(crate) fn can_be_liquidated(env: &Env, account_id: u64) -> bool {
    health_factor(env, account_id) < WAD
}
```

**File:** certora/controller/spec/index_rules.rs (L187-189)
```rust
/// The `< WAD` assertion is `is_liquidatable` (`views::can_be_liquidated`) and
/// the gate where `build_liquidation_plan` raises `HealthFactorTooHigh`, so it
/// also pins the revert condition of `get_liquidation_estimate`.
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
