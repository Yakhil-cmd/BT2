### Title
Retroactive spoke liquidation-curve change bypasses the per-position HF gate and rewrites live liquidation terms for all existing accounts - (File: contracts/controller/src/config/spoke.rs)

### Summary
The OpenQ issue is about an issuer rewriting a payout schedule after positions/claims already exist, unbalancing agreed distribution terms. The direct analog in XOXNO Lending is `set_spoke_liquidation_curve`: the liquidation curve (`liquidation_target_hf_wad`, `hf_for_max_bonus_wad`, `liquidation_bonus_factor_bps`) is deliberately **not** stamped onto positions, unlike LTV/LT/bonus/fee which are copied at position creation and only re-applied through the `THRESHOLD_UPDATE_MIN_HF_RAW` (HF ≥ 1.05) gate in `apply_gated_liquidation_params` [1](#0-0) . Every liquidation reads the curve live from `SpokeConfig` via `LiquidationCurve::from_config` [2](#0-1) . A single governance `execute` of a ready `AdminOperation::SetSpokeLiquidationCurve` op therefore retroactively changes the bonus ramp, the max-bonus knee, and the post-liquidation target HF for **every** account in the spoke — including accounts whose HF is below 1.05 and which the stamped-tuple gate explicitly protects from adverse changes [3](#0-2) [4](#0-3) .

### Finding Description
Each `AccountPosition` stores `loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` copied from the listing at creation; adverse refreshes of that tuple require hypothetical HF ≥ 1.05 when the account has debt, otherwise the old terms hold [5](#0-4) [6](#0-5) . The curve triple `(H, K, f)` that scales the bonus between the base bonus and the LT-derived maximum `M`, and that sets the close-amount target HF, is exempt from this protection: `set_spoke_liquidation_curve` validates only curve-shape constraints via `validate_liquidation_curve` and overwrites the spoke config with no account-level check [7](#0-6) . It is reachable through `AdminOperation::SetSpokeLiquidationCurve`, a normal timelocked op that any executor can trigger once ready [8](#0-7) [9](#0-8) . The bonus formula `b(HF) = base + f·(M−base)·s(HF)` with `s(HF) = min(1, (H−HF)/(H−K))`, and the repayment `x = (H·D − LT·C)/(H − LT·(1+b))`, both change discontinuously for in-flight positions [10](#0-9) [11](#0-10) .

### Impact Explanation
Theft of user funds from existing borrowers. Raising `liquidation_bonus_factor_bps` toward 10_000 and/or lowering `hf_for_max_bonus_wad` pushes the liquidation bonus toward `M` (e.g., ~8,867 bps for LT 5,300) for accounts already near or below HF 1 — collateral seizure `repay × (1+b)` grows correspondingly [12](#0-11) . Raising `target_hf_wad` enlarges the close amount `x` per liquidation, seizing more collateral per event. Crucially, this applies to accounts the stamped-tuple gate would refuse to worsen: an account at HF 1.02 keeps its old LT/bonus/fee under `update_account_threshold`, yet a curve change raises its effective bonus and close size immediately [13](#0-12) .

### Likelihood Explanation
Requires a governance op to be proposed and become ready (timelocked), then anyone may execute it — the same trust assumption the OpenQ report flags ("developers must trust the issuer"). The mitigation is social (timelock delay gives exit time) but exits are only possible for healthy accounts that can repay; accounts below the borrow/withdraw LTV gate cannot deleverage without external funds, and the gate itself shows the protocol's own standard for acceptable retroactive changes, which this path bypasses. Medium.

### Recommendation
Treat the curve like the rest of the liquidation tuple: either stamp `(H, K, f)` onto each `AccountPosition` and refresh it only through `apply_gated_liquidation_params` (with a `favors_liquidator` check extended to curve changes — higher `f`, lower `K`, higher `H` all favor liquidators), or apply the same HF ≥ 1.05 gate inside `set_spoke_liquidation_curve` by refusing/skipping the change while any debt-bearing account in the spoke would be adversely affected. At minimum, reject curve changes that increase `bonus_factor` or lower `hf_for_max_bonus` once the spoke has open borrow positions.

### Proof of Concept
1. Spoke S has default curve `(H=1.1, K=0.8, f=10_000)`; ALICE supplies USDC and borrows ETH, landing at HF ≈ 1.02 with stamped `(LT=8000, base bonus=500, fee=1200)`.
2. Governance schedules `AdminOperation::SetSpokeLiquidationCurve { spoke_id: S, target_hf_wad: 1.3e18, hf_for_max_bonus_wad: 1.0e18, liquidation_bonus_factor_bps: 10_000 }`; after the delay, anyone calls `execute`.
3. `set_spoke_liquidation_curve` stores the new curve with no per-account HF check [14](#0-13) .
4. ALICE's NAV drifts so HF = 0.99. Under the old curve `s = (1.1−0.99)/0.3 ≈ 0.367`; under the new curve `s = (1.3−0.99)/0.3 ≈ 1.0`, so the bonus jumps from ~`base + 0.37·(M−base)` to `M`, and the target repayment `x` rises with `H`. The liquidator seizes `x·(1+b)` worth of collateral — materially more than the terms ALICE opened under — even though `update_account_threshold(caller, true, [alice])` would refuse an equivalent stamped-tuple worsening at HF < 1.05 [15](#0-14) .

### Citations

**File:** contracts/controller/src/risk/params.rs (L68-93)
```rust
pub(crate) fn apply_gated_liquidation_params(
    env: &Env,
    cache: &mut Context,
    account: &Account,
    hub_asset: &HubAssetKey,
    position: &mut AccountPosition,
    effective_config: &AssetConfig,
) {
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

**File:** contracts/controller/src/risk/params.rs (L96-119)
```rust
fn favors_liquidator(position: &AccountPosition, effective_config: &AssetConfig) -> bool {
    effective_config.liquidation_threshold.raw() < position.liquidation_threshold.raw()
        || effective_config.liquidation_bonus.raw() > position.liquidation_bonus.raw()
        || effective_config.liquidation_fees.raw() < position.liquidation_fees.raw()
}

/// Checks health factor >= 1.05 with this position's threshold replaced by `new_lt`.
fn clears_min_hf(
    env: &Env,
    cache: &mut Context,
    account: &Account,
    hub_asset: &HubAssetKey,
    position: &AccountPosition,
    new_lt: Bps,
) -> bool {
    let mut hypothetical = *position;
    hypothetical.liquidation_threshold = new_lt;
    let mut supply_positions = account.supply_positions.clone();
    supply_positions.set(hub_asset.clone(), (&hypothetical).into());
    let hf =
        calculate_account_risk_totals(env, cache, &supply_positions, &account.borrow_positions)
            .health_factor;
    hf >= Wad::from(THRESHOLD_UPDATE_MIN_HF_RAW)
}
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L35-42)
```rust
impl LiquidationCurve {
    pub(crate) fn from_config(cfg: &SpokeConfig) -> Self {
        Self {
            target_hf: Wad::from(cfg.liquidation_target_hf_wad),
            hf_for_max_bonus: Wad::from(cfg.hf_for_max_bonus_wad),
            bonus_factor: Bps::from(i128::from(cfg.liquidation_bonus_factor_bps)),
        }
    }
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L60-81)
```rust
pub(crate) fn calculate_linear_bonus_with_target(
    env: &Env,
    hf: Wad,
    base: Bps,
    max: Bps,
    curve: &LiquidationCurve,
    target: Wad,
) -> Bps {
    if hf >= target {
        return base;
    }
    let scale = curve.bonus_scale(env, hf, target);

    let bonus_range = max.checked_sub(env, base);
    let bonus_increment = Wad::from(bonus_range.raw()).mul(env, scale).raw();
    let scaled_increment = curve.bonus_factor.apply_to(env, bonus_increment);
    Bps::from(
        base.raw()
            .checked_add(scaled_increment)
            .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow)),
    )
}
```

**File:** contracts/controller/src/config/spoke.rs (L52-76)
```rust
pub(crate) fn set_spoke_liquidation_curve(
    env: &Env,
    id: u32,
    target_hf_wad: i128,
    hf_for_max_bonus_wad: i128,
    liquidation_bonus_factor_bps: u32,
) {
    validate_liquidation_curve(
        env,
        target_hf_wad,
        hf_for_max_bonus_wad,
        liquidation_bonus_factor_bps,
    );

    let mut spoke = storage::get_spoke(env, id);
    spoke.liquidation_target_hf_wad = target_hf_wad;
    spoke.hf_for_max_bonus_wad = hf_for_max_bonus_wad;
    spoke.liquidation_bonus_factor_bps = liquidation_bonus_factor_bps;
    storage::set_spoke(env, id, &spoke);

    UpdateSpokeEvent {
        spoke: EventSpoke::new(id, &spoke),
    }
    .publish(env);
}
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L155-163)
```markdown
The controller computes the bonus with `max_bonus_for_threshold` and the
spoke curve. For one collateral leg, the proportion is `LT`:

    M = floor(10000 × (10000 - 5300) / 5300) = 8867 bps
    s(HF) = min(1, (H - HF) / (H - K)) = min(1, (1.06 - HF) / 0.16)
    b(HF) = b0 + f × (M - b0) × s(HF) = 500 + 0.0598 × 8367 × s(HF)

The factor 598 makes the bonus exactly 10 % at `K`:
`0.0598 × 8367 = 500.3`, rounded to 500 bps.
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L192-196)
```markdown
The target HF `H = 1.06` is equal to `LT / LTV`. A liquidation puts the
account back at the health of the LTV limit, and not higher. The repayment
is:

    x = (H × D - LT × C) / (H - LT × (1 + b))
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L372-374)
```markdown
- The curve (`H`, `K`, `f`) is not stored. Each liquidation reads it from the
  spoke. `configureSpokeCurves` changes it for all accounts of the spoke at
  the same time.
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L391-400)
```markdown
All three paths use the same gate (`apply_gated_liquidation_params`). A
change favours the liquidator when it lowers LT, raises the bonus or lowers
the fee. For an account with debt, such a change applies only when the
account HF, calculated with the new LT, is at least 1.05
(`THRESHOLD_UPDATE_MIN_HF_RAW`). If the HF is lower, the position keeps its
old LT, bonus and fee, and the call does not fail. A debt-free account always
takes the new values. In the supply path, the gate calculates the HF before
the new supply adds to the collateral. The gate reads the prices of all
assets of the account. When the gate runs, a stale price or a price outside
the band makes the call fail, also a supply.
```

**File:** tests/test-harness/tests/governance/admin_config.rs (L104-112)
```rust
    t.gov_client().execute_immediate(
        &admin,
        &AdminOperation::SetSpokeLiquidationCurve(SpokeLiquidationCurveArgs {
            spoke_id: HARNESS_SPOKE,
            target_hf_wad: 1_010_000_000_000_000_000,
            hf_for_max_bonus_wad: 990_000_000_000_000_000,
            liquidation_bonus_factor_bps: 8_000,
        }),
    );
```

**File:** contracts/controller/src/lib.rs (L633-651)
```rust
    #[only_owner]
    fn set_spoke_liquidation_curve(
        env: Env,
        id: u32,
        target_hf_wad: i128,
        hf_for_max_bonus_wad: i128,
        liquidation_bonus_factor_bps: u32,
    ) {
        renew_then!(
            env,
            config::spoke::set_spoke_liquidation_curve(
                &env,
                id,
                target_hf_wad,
                hf_for_max_bonus_wad,
                liquidation_bonus_factor_bps,
            )
        )
    }
```
